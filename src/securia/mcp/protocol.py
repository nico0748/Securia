"""JSON-RPC 2.0 と MCP の stdio トランスポート。

MCP の stdio 転送は「改行区切りの JSON-RPC 2.0」であって、それ以上のものではない。
公式 SDK を入れると実行時依存ゼロという本プロジェクトの前提が崩れるので、
プロトコルをここで直接扱う。

重要な制約: stdout に流してよいのは JSON-RPC メッセージだけ。
print() を1つ混ぜただけでクライアント側のパースが壊れるため、
ログ・診断はすべて stderr へ出す。
"""
from __future__ import annotations

import json
import sys
from dataclasses import dataclass
from typing import Any, TextIO

# JSON-RPC 2.0 の標準エラーコード
PARSE_ERROR = -32700
INVALID_REQUEST = -32600
METHOD_NOT_FOUND = -32601
INVALID_PARAMS = -32602
INTERNAL_ERROR = -32603


class JsonRpcError(Exception):
    """JSON-RPC のエラー応答へそのまま変換される例外。"""

    def __init__(self, code: int, message: str, data: Any = None) -> None:
        super().__init__(message)
        self.code = code
        self.message = message
        self.data = data

    def to_error(self) -> dict:
        err: dict[str, Any] = {"code": self.code, "message": self.message}
        if self.data is not None:
            err["data"] = self.data
        return err


class InvalidParams(JsonRpcError):
    def __init__(self, message: str, data: Any = None) -> None:
        super().__init__(INVALID_PARAMS, message, data)


@dataclass(frozen=True)
class Message:
    """受信した1件の JSON-RPC メッセージ。

    id が None のものは通知（notification）で、応答を返してはいけない。
    """

    method: str
    params: dict
    id: Any = None

    @property
    def is_notification(self) -> bool:
        return self.id is None


def parse_message(payload: Any) -> Message:
    """デコード済みの JSON を Message にする。形が不正なら JsonRpcError。"""
    if not isinstance(payload, dict):
        raise JsonRpcError(INVALID_REQUEST, "リクエストはオブジェクトである必要があります")
    if payload.get("jsonrpc") != "2.0":
        raise JsonRpcError(INVALID_REQUEST, "jsonrpc は '2.0' である必要があります")

    method = payload.get("method")
    if not isinstance(method, str) or not method:
        raise JsonRpcError(INVALID_REQUEST, "method が指定されていません")

    params = payload.get("params", {})
    if params is None:
        params = {}
    if not isinstance(params, dict):
        # 配列形式の params は MCP では使わない
        raise InvalidParams("params はオブジェクトである必要があります")

    return Message(method=method, params=params, id=payload.get("id"))


def make_response(request_id: Any, result: Any) -> dict:
    return {"jsonrpc": "2.0", "id": request_id, "result": result}


def make_error(request_id: Any, code: int, message: str, data: Any = None) -> dict:
    error: dict[str, Any] = {"code": code, "message": message}
    if data is not None:
        error["data"] = data
    return {"jsonrpc": "2.0", "id": request_id, "error": error}


class StdioTransport:
    """改行区切り JSON のやり取り。

    1メッセージ = 1行。メッセージ内に生の改行は入らない（json.dumps が
    エスケープする）ので、行単位で読めば十分。
    """

    def __init__(self, reader: TextIO | None = None, writer: TextIO | None = None) -> None:
        self.reader = reader if reader is not None else sys.stdin
        self.writer = writer if writer is not None else sys.stdout

    def read(self) -> Any | None:
        """次のメッセージを返す。EOF なら None。

        JSON として壊れている行は ValueError を投げる（呼び出し側が
        parse error として応答する）。空行は読み飛ばす。
        """
        while True:
            line = self.reader.readline()
            if line == "":
                return None          # EOF
            line = line.strip()
            if not line:
                continue             # 空行は無視
            return json.loads(line)

    def write(self, message: dict) -> None:
        self.writer.write(json.dumps(message, ensure_ascii=False, separators=(",", ":")) + "\n")
        self.writer.flush()


def log(message: str) -> None:
    """診断出力。stdout はプロトコル専用なので必ず stderr へ。"""
    print(f"[securia-mcp] {message}", file=sys.stderr, flush=True)


def require_str(params: dict, key: str, *, default: str | None = None) -> str:
    value = params.get(key, default)
    if value is None:
        raise InvalidParams(f"{key} は必須です")
    if not isinstance(value, str) or not value.strip():
        raise InvalidParams(f"{key} は空でない文字列である必要があります")
    return value.strip()


def optional_str(params: dict, key: str) -> str | None:
    value = params.get(key)
    if value is None:
        return None
    if not isinstance(value, str):
        raise InvalidParams(f"{key} は文字列である必要があります")
    stripped = value.strip()
    return stripped or None


def optional_int(params: dict, key: str, *, default: int | None = None,
                 minimum: int | None = None, maximum: int | None = None) -> int | None:
    value = params.get(key, default)
    if value is None:
        return None
    if isinstance(value, bool) or not isinstance(value, int):
        raise InvalidParams(f"{key} は整数である必要があります")
    if minimum is not None and value < minimum:
        raise InvalidParams(f"{key} は {minimum} 以上である必要があります")
    if maximum is not None and value > maximum:
        value = maximum          # 上限は黙って丸める（呼び出し側を失敗させない）
    return value


def optional_bool(params: dict, key: str, *, default: bool = False) -> bool:
    value = params.get(key, default)
    if not isinstance(value, bool):
        raise InvalidParams(f"{key} は true/false である必要があります")
    return value


__all__ = [
    "INTERNAL_ERROR",
    "INVALID_PARAMS",
    "INVALID_REQUEST",
    "METHOD_NOT_FOUND",
    "PARSE_ERROR",
    "InvalidParams",
    "JsonRpcError",
    "Message",
    "StdioTransport",
    "log",
    "make_error",
    "make_response",
    "optional_bool",
    "optional_int",
    "optional_str",
    "parse_message",
    "require_str",
]
