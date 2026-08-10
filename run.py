#!/usr/bin/env python3
"""Securify Local — ローカル脆弱性スキャナ (追加インストール不要 / 標準ライブラリのみ)

使い方:
    python3 run.py                 # 127.0.0.1:8787 で起動しブラウザを開く
    python3 run.py --port 9000     # ポート指定
    python3 run.py --path ~/proj   # 起動時の初期対象フォルダを指定
    python3 run.py --no-browser    # ブラウザ自動起動なし
    python3 run.py --cli ~/proj    # サーバを立てずCLIでスキャンしJSON出力
"""
from __future__ import annotations

import argparse
import json
import os
import sys
import threading
import webbrowser
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer
from urllib.parse import urlparse, parse_qs

sys.path.insert(0, os.path.dirname(os.path.abspath(__file__)))
from scanner import run_scan  # noqa: E402

WEB_DIR = os.path.join(os.path.dirname(os.path.abspath(__file__)), "web")
DEFAULT_PATH = {"value": os.getcwd()}


class Handler(BaseHTTPRequestHandler):
    def _send(self, code, body, ctype="application/json; charset=utf-8"):
        if isinstance(body, (dict, list)):
            body = json.dumps(body, ensure_ascii=False).encode("utf-8")
        elif isinstance(body, str):
            body = body.encode("utf-8")
        self.send_response(code)
        self.send_header("Content-Type", ctype)
        self.send_header("Content-Length", str(len(body)))
        self.send_header("Cache-Control", "no-store")
        self.end_headers()
        self.wfile.write(body)

    def do_GET(self):
        parsed = urlparse(self.path)
        path = parsed.path
        if path in ("/", "/index.html"):
            self._serve_file("index.html", "text/html; charset=utf-8")
        elif path == "/api/default-path":
            self._send(200, {"path": DEFAULT_PATH["value"]})
        elif path == "/api/scan":
            qs = parse_qs(parsed.query)
            target = (qs.get("path") or [DEFAULT_PATH["value"]])[0]
            self._run_scan(target)
        else:
            self._send(404, {"error": "not found"})

    def _serve_file(self, name, ctype):
        fp = os.path.join(WEB_DIR, name)
        if not os.path.isfile(fp):
            self._send(404, "not found", "text/plain; charset=utf-8")
            return
        with open(fp, "rb") as f:
            data = f.read()
        self._send(200, data.decode("utf-8"), ctype)

    def _run_scan(self, target):
        try:
            result = run_scan(target)
            self._send(200, result)
        except NotADirectoryError as e:
            self._send(400, {"error": str(e)})
        except Exception as e:  # noqa: BLE001
            self._send(500, {"error": f"スキャン中にエラー: {e}"})

    def log_message(self, fmt, *args):  # ログを簡潔に
        sys.stderr.write("[securify-local] %s\n" % (fmt % args))


def serve(port, open_browser):
    server = ThreadingHTTPServer(("127.0.0.1", port), Handler)
    url = f"http://127.0.0.1:{port}/"
    print(f"\n  Securify Local を起動しました → {url}")
    print("  対象フォルダを入力して『スキャン実行』を押してください。")
    print("  停止するには Ctrl+C。\n")
    if open_browser:
        threading.Timer(0.8, lambda: webbrowser.open(url)).start()
    try:
        server.serve_forever()
    except KeyboardInterrupt:
        print("\n  停止しました。")
        server.shutdown()


def main():
    ap = argparse.ArgumentParser(description="Securify Local — ローカル脆弱性スキャナ")
    ap.add_argument("--port", type=int, default=8787)
    ap.add_argument("--path", default=os.getcwd(), help="初期対象フォルダ")
    ap.add_argument("--no-browser", action="store_true")
    ap.add_argument("--cli", metavar="DIR", help="サーバを立てずCLIでスキャン")
    ap.add_argument("--out", help="--cli時の出力JSONファイル")
    args = ap.parse_args()

    if args.cli:
        result = run_scan(args.cli)
        text = json.dumps(result, ensure_ascii=False, indent=2)
        if args.out:
            with open(args.out, "w", encoding="utf-8") as f:
                f.write(text)
            print(f"結果を書き出しました: {args.out}")
        else:
            print(text)
        s = result["summary"]["severity_counts"]
        print(f"\n検出: CRITICAL={s['CRITICAL']} HIGH={s['HIGH']} MEDIUM={s['MEDIUM']} LOW={s['LOW']} INFO={s['INFO']}",
              file=sys.stderr)
        return

    DEFAULT_PATH["value"] = os.path.abspath(os.path.expanduser(args.path))
    serve(args.port, not args.no_browser)


if __name__ == "__main__":
    main()
