"""ローカル HTTP サーバ。

セキュリティ上の前提を明示しておく。このサーバは 127.0.0.1 にしか
bind しないが、それだけでは「ブラウザ経由で外部サイトから叩かれる」
攻撃を防げない。攻撃者のドメインを 127.0.0.1 に解決させる DNS
リバインディングを使えば、被害者のブラウザは同一オリジンとして
このサーバへリクエストできてしまう。スキャン結果にはハードコードされた
秘密情報の在り処が含まれるため、実質的な情報漏洩経路になる。

そこで3段構えにする。
  1. Host ヘッダ検証 — リバインドされたリクエストは Host が攻撃者の
     ドメインになるので弾ける。これが主防御。
  2. 起動時に生成するトークン — ページ配信時に埋め込み、API 呼び出しに
     必須とする。同一オリジンでないと読み出せない。
  3. Origin ヘッダ検証 — クロスオリジンからの状態変更を拒否する。

加えて、スキャン対象パスは securia.toml の allowed_roots 配下に限定する。
"""
from __future__ import annotations

import json
import mimetypes
import secrets
import threading
import webbrowser
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer
from pathlib import Path
from urllib.parse import parse_qs, urlparse

from . import __version__
from .config import Config
from .jobs import JobBusy, JobManager
from .osv import OsvClient
from .paths import PathNotAllowed, ensure_scannable, normalize
from .scan import all_rule_ids
from .scan.walker import read_snippet
from .store import Store

WEB_DIR = Path(__file__).parent / "web"
TOKEN_PLACEHOLDER = "__SECURIA_TOKEN__"
MAX_BODY_BYTES = 64 * 1024


class AppContext:
    """ハンドラ間で共有する状態。"""

    def __init__(self, cfg: Config, store: Store, port: int) -> None:
        self.cfg = cfg
        self.store = store
        self.port = port
        self.token = secrets.token_urlsafe(32)
        self.jobs = JobManager(store, cfg)
        self.default_path = str(Path.cwd())

    def new_osv_client(self) -> OsvClient | None:
        if not self.cfg.osv.enabled:
            return None
        return OsvClient(self.cfg.osv, cache=self.store)

    def allowed_hosts(self) -> set[str]:
        return {
            f"127.0.0.1:{self.port}", f"localhost:{self.port}", f"[::1]:{self.port}",
        }

    def allowed_origins(self) -> set[str]:
        return {
            f"http://127.0.0.1:{self.port}", f"http://localhost:{self.port}", f"http://[::1]:{self.port}",
        }


class HttpError(Exception):
    def __init__(self, code: int, message: str) -> None:
        super().__init__(message)
        self.code = code
        self.message = message


class Handler(BaseHTTPRequestHandler):
    server_version = f"Securia/{__version__}"
    protocol_version = "HTTP/1.1"
    ctx: AppContext  # ThreadingHTTPServer 側で注入する

    # ---------------- 送信ヘルパ ----------------
    def _send_bytes(self, code: int, body: bytes, ctype: str, extra: dict | None = None) -> None:
        self.send_response(code)
        self.send_header("Content-Type", ctype)
        self.send_header("Content-Length", str(len(body)))
        self.send_header("Cache-Control", "no-store")
        self.send_header("X-Content-Type-Options", "nosniff")
        self.send_header("Referrer-Policy", "no-referrer")
        # 外部リソースを一切読み込まない前提の CSP。
        # style-src に 'unsafe-inline' があるのは、棒グラフの幅など動的な寸法を
        # style 属性で与えているため。スクリプトは 'self' のみで、挿入する文字列は
        # すべて app.js の esc() を通す。
        self.send_header(
            "Content-Security-Policy",
            "default-src 'none'; script-src 'self'; style-src 'self' 'unsafe-inline'; "
            "img-src 'self' data:; connect-src 'self'; base-uri 'none'; form-action 'none'; "
            "frame-ancestors 'none'",
        )
        for k, v in (extra or {}).items():
            self.send_header(k, v)
        self.end_headers()
        if self.command != "HEAD":
            self.wfile.write(body)

    def _send_json(self, code: int, payload: object) -> None:
        self._send_bytes(code, json.dumps(payload, ensure_ascii=False).encode("utf-8"),
                         "application/json; charset=utf-8")

    def _read_json(self) -> dict:
        length = int(self.headers.get("Content-Length") or 0)
        if length <= 0:
            return {}
        if length > MAX_BODY_BYTES:
            raise HttpError(413, "リクエストが大きすぎます")
        try:
            data = json.loads(self.rfile.read(length).decode("utf-8"))
        except (ValueError, UnicodeDecodeError) as e:
            raise HttpError(400, f"JSON として読めません: {e}") from e
        if not isinstance(data, dict):
            raise HttpError(400, "オブジェクトを送ってください")
        return data

    # ---------------- セキュリティ検査 ----------------
    def _check_host(self) -> None:
        host = (self.headers.get("Host") or "").strip().lower()
        if host not in self.ctx.allowed_hosts():
            # DNS リバインディングの疑い。詳細は返さない。
            raise HttpError(403, "Host ヘッダが不正です")

    def _check_origin(self) -> None:
        origin = self.headers.get("Origin")
        if origin and origin not in self.ctx.allowed_origins():
            raise HttpError(403, "オリジンが許可されていません")

    def _check_token(self) -> None:
        provided = self.headers.get("X-Securia-Token") or ""
        if not secrets.compare_digest(provided, self.ctx.token):
            raise HttpError(401, "認証トークンが不正です。ページを再読み込みしてください。")

    # ---------------- ルーティング ----------------
    def do_GET(self) -> None:      # noqa: N802
        self._dispatch("GET")

    def do_HEAD(self) -> None:     # noqa: N802
        self._dispatch("GET")

    def do_POST(self) -> None:     # noqa: N802
        self._dispatch("POST")

    def do_DELETE(self) -> None:   # noqa: N802
        self._dispatch("DELETE")

    def _dispatch(self, method: str) -> None:
        parsed = urlparse(self.path)
        path = parsed.path
        query = parse_qs(parsed.query)
        try:
            self._check_host()
            if path.startswith("/api/"):
                self._check_origin()
                self._check_token()
                self._route_api(method, path, query)
            elif method == "GET":
                self._route_static(path)
            else:
                raise HttpError(405, "許可されていないメソッドです")
        except HttpError as e:
            self._send_json(e.code, {"error": e.message})
        except BrokenPipeError:
            pass  # クライアントが切断した（SSE では通常のこと）
        except Exception as e:  # noqa: BLE001
            self._send_json(500, {"error": f"内部エラー: {type(e).__name__}: {e}"})

    def _route_static(self, path: str) -> None:
        if path in ("/", "/index.html"):
            html = (WEB_DIR / "index.html").read_text(encoding="utf-8")
            html = html.replace(TOKEN_PLACEHOLDER, self.ctx.token)
            self._send_bytes(200, html.encode("utf-8"), "text/html; charset=utf-8")
            return

        name = path.lstrip("/")
        # パストラバーサル防止: 単純名のみ許可する
        if "/" in name or ".." in name or not name:
            raise HttpError(404, "見つかりません")
        target = WEB_DIR / name
        if not target.is_file():
            raise HttpError(404, "見つかりません")
        ctype = mimetypes.guess_type(name)[0] or "application/octet-stream"
        if ctype.startswith("text/") or ctype in ("application/javascript",):
            ctype += "; charset=utf-8"
        self._send_bytes(200, target.read_bytes(), ctype)

    def _route_api(self, method: str, path: str, query: dict[str, list[str]]) -> None:
        parts = [p for p in path.split("/") if p][1:]  # "api" を落とす

        match (method, parts):
            case ("GET", ["state"]):
                self._api_state()
            case ("GET", ["rules"]):
                self._send_json(200, {"rules": all_rule_ids()})
            case ("POST", ["scans"]):
                self._api_start_scan()
            case ("GET", ["scans"]):
                target = (query.get("target") or [None])[0]
                limit = _int_arg(query, "limit", 50, 1, 500)
                self._send_json(200, {"scans": self.ctx.store.list_scans(target, limit)})
            case ("GET", ["scans", scan_id]):
                self._api_get_scan(scan_id)
            case ("GET", ["targets"]):
                self._send_json(200, {"targets": self.ctx.store.list_targets()})
            case ("GET", ["jobs"]):
                self._send_json(200, {"jobs": self.ctx.jobs.list_jobs()})
            case ("GET", ["jobs", job_id]):
                self._api_get_job(job_id)
            case ("GET", ["jobs", job_id, "events"]):
                self._api_job_events(job_id)
            case ("DELETE", ["jobs", job_id]):
                self._api_cancel_job(job_id)
            case ("GET", ["suppressions"]):
                target = (query.get("target") or [None])[0]
                self._send_json(200, {"suppressions": self.ctx.store.list_suppressions(target)})
            case ("POST", ["suppressions"]):
                self._api_suppress()
            case ("DELETE", ["suppressions", fingerprint]):
                self._api_unsuppress(fingerprint)
            case ("GET", ["snippet"]):
                self._api_snippet(query)
            case _:
                raise HttpError(404, "そのエンドポイントはありません")

    # ---------------- API 実装 ----------------
    def _api_state(self) -> None:
        cfg = self.ctx.cfg
        self._send_json(200, {
            "version": __version__,
            "default_path": self.ctx.default_path,
            "allowed_roots": cfg.scan.allowed_roots,
            "osv_enabled": cfg.osv.enabled,
            "config_source": str(cfg.source) if cfg.source else None,
            "targets": self.ctx.store.list_targets(),
        })

    def _api_start_scan(self) -> None:
        body = self._read_json()
        raw_path = str(body.get("path") or "").strip()
        if not raw_path:
            raise HttpError(400, "path を指定してください")
        try:
            target = ensure_scannable(raw_path, self.ctx.cfg.scan.allowed_roots)
        except PathNotAllowed as e:
            raise HttpError(400, str(e)) from e
        try:
            job = self.ctx.jobs.start(target, self.ctx.new_osv_client())
        except JobBusy as e:
            raise HttpError(429, str(e)) from e
        self.ctx.default_path = str(target)
        self._send_json(202, job.snapshot())

    def _api_get_job(self, job_id: str) -> None:
        job = self.ctx.jobs.get(job_id)
        if job is None:
            raise HttpError(404, "ジョブが見つかりません")
        payload = job.snapshot()
        if job.payload is not None:
            payload["result"] = job.payload
        self._send_json(200, payload)

    def _api_cancel_job(self, job_id: str) -> None:
        # 「存在しない」と「既に終わっている」は呼び出し側にとって別の話なので分ける。
        job = self.ctx.jobs.get(job_id)
        if job is None:
            raise HttpError(404, "ジョブが見つかりません")
        if not self.ctx.jobs.cancel(job_id):
            raise HttpError(409, f"実行中ではありません（状態: {job.state}）")
        self._send_json(200, {"cancelled": job_id})

    def _api_job_events(self, job_id: str) -> None:
        job = self.ctx.jobs.get(job_id)
        if job is None:
            raise HttpError(404, "ジョブが見つかりません")

        self.send_response(200)
        self.send_header("Content-Type", "text/event-stream; charset=utf-8")
        self.send_header("Cache-Control", "no-store")
        self.send_header("X-Content-Type-Options", "nosniff")
        self.send_header("Connection", "close")
        self.end_headers()
        self.close_connection = True

        try:
            for event in self.ctx.jobs.subscribe(job_id):
                self._write_sse(event)
        except (BrokenPipeError, ConnectionResetError):
            return

    def _write_sse(self, event: dict) -> None:
        data = json.dumps(event, ensure_ascii=False)
        self.wfile.write(f"data: {data}\n\n".encode())
        self.wfile.flush()

    def _api_get_scan(self, raw_id: str) -> None:
        try:
            scan_id = int(raw_id)
        except ValueError as e:
            raise HttpError(400, "スキャン ID が不正です") from e
        scan = self.ctx.store.get_scan(scan_id)
        if scan is None:
            raise HttpError(404, "スキャンが見つかりません")
        findings = self.ctx.store.load_findings(scan_id)
        components = self.ctx.store.load_components(scan_id)
        self._send_json(200, {
            **scan,
            "findings": [f.to_dict() for f in findings],
            "components": [c.to_dict() for c in components],
            "suppressed_fingerprints": sorted(self.ctx.store.suppressed_fingerprints(scan["target"])),
        })

    def _api_suppress(self) -> None:
        body = self._read_json()
        target = str(body.get("target") or "").strip()
        fingerprint = str(body.get("fingerprint") or "").strip()
        if not target or not fingerprint:
            raise HttpError(400, "target と fingerprint が必要です")
        self.ctx.store.suppress_raw(
            target, fingerprint,
            reason=str(body.get("reason") or ""),
            rule_id=str(body.get("rule_id") or ""),
            file=str(body.get("file") or ""),
            title=str(body.get("title") or ""),
        )
        self._send_json(201, {"suppressed": fingerprint})

    def _api_unsuppress(self, fingerprint: str) -> None:
        parsed = urlparse(self.path)
        target = (parse_qs(parsed.query).get("target") or [""])[0]
        if not target:
            raise HttpError(400, "target を指定してください")
        ok = self.ctx.store.unsuppress(target, fingerprint)
        self._send_json(200 if ok else 404,
                        {"unsuppressed": fingerprint} if ok else {"error": "抑制が見つかりません"})

    def _api_snippet(self, query: dict[str, list[str]]) -> None:
        target = (query.get("target") or [""])[0]
        rel = (query.get("file") or [""])[0]
        line = _int_arg(query, "line", 0, 0, 10_000_000)
        if not target or not rel:
            raise HttpError(400, "target と file が必要です")
        try:
            root = ensure_scannable(target, self.ctx.cfg.scan.allowed_roots)
        except PathNotAllowed as e:
            raise HttpError(400, str(e)) from e

        # rel はブラウザから来る。root の外を指させない。
        candidate = normalize(root / rel)
        try:
            candidate.relative_to(root)
        except ValueError as e:
            raise HttpError(400, "対象ディレクトリの外は読めません") from e
        if not candidate.is_file():
            raise HttpError(404, "ファイルが見つかりません")

        self._send_json(200, {"file": rel, "line": line, "lines": read_snippet(candidate, line)})

    # ---------------- ログ ----------------
    def log_message(self, fmt: str, *args: object) -> None:
        # アクセスログは既定で出さない。静かなローカルツールにする。
        pass

    def log_error(self, fmt: str, *args: object) -> None:
        pass


def _int_arg(query: dict[str, list[str]], key: str, default: int, lo: int, hi: int) -> int:
    raw = (query.get(key) or [None])[0]
    if raw is None:
        return default
    try:
        value = int(raw)
    except ValueError as e:
        raise HttpError(400, f"{key} は整数で指定してください") from e
    return max(lo, min(hi, value))


def serve(cfg: Config, store: Store, *, port: int | None = None,
          open_browser: bool | None = None, initial_path: str | None = None) -> None:
    """サーバを起動してブロックする。Ctrl+C で停止。"""
    port = port if port is not None else cfg.server.port
    should_open = cfg.server.open_browser if open_browser is None else open_browser

    ctx = AppContext(cfg, store, port)
    if initial_path:
        ctx.default_path = str(normalize(initial_path))

    handler = type("BoundHandler", (Handler,), {"ctx": ctx})
    httpd = ThreadingHTTPServer(("127.0.0.1", port), handler)
    httpd.daemon_threads = True

    url = f"http://127.0.0.1:{port}/"
    print(f"\n  Securia {__version__} を起動しました → {url}")
    if cfg.source:
        print(f"  設定: {cfg.source}")
    print(f"  スキャン許可ルート: {', '.join(cfg.scan.allowed_roots) or '(制限なし)'}")
    print("  停止するには Ctrl+C。\n")

    if should_open:
        threading.Timer(0.6, lambda: webbrowser.open(url)).start()

    try:
        httpd.serve_forever()
    except KeyboardInterrupt:
        print("\n  停止しました。")
    finally:
        httpd.shutdown()
        httpd.server_close()
