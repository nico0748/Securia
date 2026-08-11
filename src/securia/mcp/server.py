"""MCP サーバー本体。

Claude などの MCP クライアントから Securia を操作できるようにする。
転送は stdio、プロトコルは JSON-RPC 2.0。

スキャンは同期的に実行する。処理中はクライアントが待つが、走査は1パスに
統合済みで実測でも速いため、非同期化の複雑さに見合わない。
"""
from __future__ import annotations

import json
from typing import Any

from .. import __version__
from ..config import Config
from ..store import Store
from . import tools as toolmod
from .protocol import (
    INTERNAL_ERROR,
    INVALID_REQUEST,
    METHOD_NOT_FOUND,
    PARSE_ERROR,
    JsonRpcError,
    Message,
    StdioTransport,
    log,
    make_error,
    make_response,
    parse_message,
    require_str,
)

# 対応するプロトコル版。クライアントが知っている版を提示してきたらそれに合わせ、
# 知らない版なら我々の最新を返して折衝する（MCP の規定どおり）。
LATEST_PROTOCOL_VERSION = "2025-06-18"
SUPPORTED_PROTOCOL_VERSIONS = ("2025-06-18", "2025-03-26", "2024-11-05")

SERVER_INSTRUCTIONS = """\
Securia はローカルで完結する脆弱性スキャナです。依存関係(SBOM と OSV.dev の CVE 照合)、
静的コード解析(ハードコードされた秘密情報・危険な関数・TLS 検証の無効化など)、
設定ファイル診断(Dockerfile / Terraform / Kubernetes / GitHub Actions など)を行います。

使い方の流れ:
1. securia_scan でディレクトリをスキャンする。要約と重要度の高い検出が返る。
2. 全件や絞り込みが要るときは、返ってきた scan_id を securia_list_findings に渡す。
3. 個々の検出は securia_get_finding で詳細と該当コードを確認する。
4. 誤検知だと確認できたものだけ securia_suppress で抑制する。

注意:
- スキャン対象は設定の allowed_roots 配下に限られます。範囲外はエラーになります。
- ルールは正規表現ベースなので誤検知は起こります。抑制する前に必ず
  securia_get_finding で実際のコードを読んで判断してください。
- 検出件数は多くなりがちです。まず min_severity で絞ってから広げてください。
"""


class McpServer:
    """1本の stdio 接続を処理する MCP サーバー。"""

    def __init__(self, cfg: Config, store: Store) -> None:
        self.cfg = cfg
        self.store = store
        self.registry = toolmod.build_registry(cfg, store)
        self.initialized = False
        self.protocol_version = LATEST_PROTOCOL_VERSION

    # ---------------- ループ ----------------
    def serve(self, transport: StdioTransport | None = None) -> None:
        """EOF まで読み続ける。"""
        transport = transport or StdioTransport()
        while True:
            try:
                payload = transport.read()
            except json.JSONDecodeError as e:
                transport.write(make_error(None, PARSE_ERROR, f"JSON として読めません: {e}"))
                continue
            except (KeyboardInterrupt, EOFError):
                return
            if payload is None:
                return                       # EOF: クライアントが切断した

            response = self.handle(payload)
            if response is not None:
                transport.write(response)

    def handle(self, payload: Any) -> dict | None:
        """1メッセージを処理する。通知なら None を返す（応答してはいけない）。"""
        try:
            message = parse_message(payload)
        except JsonRpcError as e:
            request_id = payload.get("id") if isinstance(payload, dict) else None
            return make_error(request_id, e.code, e.message, e.data)

        try:
            if message.is_notification:
                self._handle_notification(message)
                return None
            result = self._handle_request(message)
            return make_response(message.id, result)
        except JsonRpcError as e:
            return make_error(message.id, e.code, e.message, e.data)
        except Exception as e:  # noqa: BLE001 — 1つの失敗でサーバーを落とさない
            log(f"未処理の例外: {type(e).__name__}: {e}")
            return make_error(message.id, INTERNAL_ERROR, f"内部エラー: {type(e).__name__}: {e}")

    # ---------------- 振り分け ----------------
    def _handle_notification(self, message: Message) -> None:
        if message.method == "notifications/initialized":
            self.initialized = True
        # cancelled / progress などは黙って無視する。未知の通知に応答しないのが規定。

    def _handle_request(self, message: Message) -> dict:
        method = message.method

        if method == "initialize":
            return self._initialize(message.params)
        if method == "ping":
            return {}

        # 初期化前に機能を使わせない（規定では initialize と ping のみ許される）
        if not self.initialized:
            raise JsonRpcError(INVALID_REQUEST, "initialize が完了していません")

        match method:
            case "tools/list":
                return {"tools": self.registry.list_specs()}
            case "tools/call":
                return self._call_tool(message.params)
            case "resources/list":
                return {"resources": toolmod.list_resources(self.cfg, self.store)}
            case "resources/templates/list":
                return {"resourceTemplates": toolmod.list_resource_templates()}
            case "resources/read":
                return self._read_resource(message.params)
            case "prompts/list":
                return {"prompts": []}
            case _:
                raise JsonRpcError(METHOD_NOT_FOUND, f"未知のメソッドです: {method}")

    # ---------------- 各メソッド ----------------
    def _initialize(self, params: dict) -> dict:
        requested = params.get("protocolVersion")
        if isinstance(requested, str) and requested in SUPPORTED_PROTOCOL_VERSIONS:
            self.protocol_version = requested
        else:
            self.protocol_version = LATEST_PROTOCOL_VERSION

        client = params.get("clientInfo") or {}
        if isinstance(client, dict) and client.get("name"):
            log(f"接続: {client.get('name')} {client.get('version', '')}".strip())

        # initialize の応答時点ではまだ initialized 通知を受けていないが、
        # 通知を送らないクライアントもあるため、ここで使用可能にしておく。
        self.initialized = True

        return {
            "protocolVersion": self.protocol_version,
            "capabilities": {
                "tools": {"listChanged": False},
                "resources": {"listChanged": False, "subscribe": False},
            },
            "serverInfo": {"name": "securia", "title": "Securia 脆弱性スキャナ", "version": __version__},
            "instructions": SERVER_INSTRUCTIONS,
        }

    def _call_tool(self, params: dict) -> dict:
        name = require_str(params, "name")
        arguments = params.get("arguments") or {}
        if not isinstance(arguments, dict):
            raise JsonRpcError(INVALID_REQUEST, "arguments はオブジェクトである必要があります")

        try:
            text = self.registry.call(name, arguments)
        except toolmod.ToolError as e:
            # 実行時の失敗はプロトコルエラーにせず結果として返す。
            # 呼び出し側のモデルが内容を読んで引数を直せるようにするため。
            return {"content": [{"type": "text", "text": f"エラー: {e}"}], "isError": True}
        except JsonRpcError as e:
            return {"content": [{"type": "text", "text": f"エラー: {e.message}"}], "isError": True}
        except Exception as e:  # noqa: BLE001
            log(f"ツール {name} が失敗: {type(e).__name__}: {e}")
            return {
                "content": [{"type": "text", "text": f"エラー: {type(e).__name__}: {e}"}],
                "isError": True,
            }

        return {"content": [{"type": "text", "text": text}], "isError": False}

    def _read_resource(self, params: dict) -> dict:
        uri = require_str(params, "uri")
        try:
            contents = toolmod.read_resource(self.cfg, self.store, uri)
        except toolmod.ToolError as e:
            raise JsonRpcError(INVALID_REQUEST, str(e)) from e
        return {"contents": [contents]}


def serve_stdio(cfg: Config, store: Store) -> None:
    """stdio で MCP サーバーを動かす。EOF まで戻らない。"""
    log(f"Securia {__version__} MCP サーバーを開始しました（stdio）")
    roots = ", ".join(cfg.scan.allowed_roots) or "(制限なし)"
    log(f"スキャン許可ルート: {roots}")
    McpServer(cfg, store).serve()
    log("終了しました")
