"""HTTP サーバ。とくにセキュリティ検査（Host / トークン / Origin / パス制限）。"""
from __future__ import annotations

import json
import threading
import time
from http.client import HTTPConnection
from http.server import ThreadingHTTPServer
from pathlib import Path

import pytest

from securia.config import Config, ScanConfig
from securia.server import AppContext, Handler
from securia.store import Store


class Client:
    """テスト用の薄い HTTP クライアント。ヘッダを自由に差し替えられる。"""

    def __init__(self, port: int, token: str) -> None:
        self.port = port
        self.token = token

    def request(self, method: str, path: str, *, body: dict | None = None,
                token: str | None = "__default__", host: str | None = None,
                origin: str | None = None) -> tuple[int, dict]:
        headers: dict[str, str] = {"Host": host or f"127.0.0.1:{self.port}"}
        if token == "__default__":
            headers["X-Securia-Token"] = self.token
        elif token is not None:
            headers["X-Securia-Token"] = token
        if origin is not None:
            headers["Origin"] = origin

        payload = None
        if body is not None:
            payload = json.dumps(body).encode("utf-8")
            headers["Content-Type"] = "application/json"

        conn = HTTPConnection("127.0.0.1", self.port, timeout=15)
        try:
            conn.request(method, path, body=payload, headers=headers)
            response = conn.getresponse()
            raw = response.read()
            try:
                data = json.loads(raw.decode("utf-8"))
            except (ValueError, UnicodeDecodeError):
                data = {"_raw": raw[:200].decode("utf-8", "replace")}
            return response.status, data
        finally:
            conn.close()

    def get(self, path: str, **kw) -> tuple[int, dict]:
        return self.request("GET", path, **kw)

    def post(self, path: str, **kw) -> tuple[int, dict]:
        return self.request("POST", path, **kw)

    def delete(self, path: str, **kw) -> tuple[int, dict]:
        return self.request("DELETE", path, **kw)

    def wait_for_job(self, job_id: str, timeout: float = 30.0) -> dict:
        deadline = time.time() + timeout
        while time.time() < deadline:
            _, job = self.get(f"/api/jobs/{job_id}")
            if job.get("state") != "running":
                return job
            time.sleep(0.05)
        raise AssertionError("ジョブが時間内に終わりませんでした")


@pytest.fixture
def project(tmp_path: Path) -> Path:
    root = tmp_path / "project"
    root.mkdir()
    (root / "app.py").write_text('KEY = "AKIAIOSFODNN7EXAMPLE"\nos.system(x)\n', encoding="utf-8")
    return root


@pytest.fixture
def server(tmp_path: Path):
    cfg = Config()
    cfg.scan = ScanConfig(allowed_roots=[str(tmp_path)])
    cfg.osv.enabled = False

    store = Store(tmp_path / "server.db")
    ctx = AppContext(cfg, store, port=0)
    handler = type("TestHandler", (Handler,), {"ctx": ctx})

    httpd = ThreadingHTTPServer(("127.0.0.1", 0), handler)
    httpd.daemon_threads = True
    ctx.port = httpd.server_address[1]      # 実際に割り当たったポートで Host 検証する

    thread = threading.Thread(target=httpd.serve_forever, daemon=True)
    thread.start()
    try:
        yield Client(ctx.port, ctx.token), ctx
    finally:
        httpd.shutdown()
        httpd.server_close()
        store.close()


# ---------------- セキュリティ ----------------
def test_rejects_foreign_host_header(server) -> None:
    """DNS リバインディングではリクエストの Host が攻撃者のドメインになる。"""
    client, _ = server
    status, body = client.get("/api/state", host="evil.example.com")
    assert status == 403
    assert "Host" in body["error"]


def test_rejects_foreign_host_on_static_pages_too(server) -> None:
    client, _ = server
    status, _ = client.get("/", host="evil.example.com")
    assert status == 403


@pytest.mark.parametrize("host_template", ["127.0.0.1:{port}", "localhost:{port}"])
def test_accepts_loopback_hosts(server, host_template: str) -> None:
    client, _ = server
    status, _ = client.get("/api/state", host=host_template.format(port=client.port))
    assert status == 200


def test_requires_token(server) -> None:
    client, _ = server
    assert client.get("/api/state", token=None)[0] == 401
    assert client.get("/api/state", token="wrong-token")[0] == 401


def test_static_pages_do_not_require_token(server) -> None:
    """ページ本体は素で取れる。トークンはその中に埋め込まれている。"""
    client, _ = server
    status, body = client.get("/", token=None)
    assert status == 200
    assert "securia-token" in body["_raw"]


def test_rejects_cross_origin(server) -> None:
    client, _ = server
    status, _ = client.get("/api/state", origin="https://evil.example.com")
    assert status == 403


def test_accepts_same_origin(server) -> None:
    client, _ = server
    status, _ = client.get("/api/state", origin=f"http://127.0.0.1:{client.port}")
    assert status == 200


def test_security_headers_present(server) -> None:
    client, _ = server
    conn = HTTPConnection("127.0.0.1", client.port, timeout=10)
    conn.request("GET", "/", headers={"Host": f"127.0.0.1:{client.port}"})
    response = conn.getresponse()
    response.read()
    assert "default-src 'none'" in response.getheader("Content-Security-Policy")
    assert response.getheader("X-Content-Type-Options") == "nosniff"
    assert response.getheader("Referrer-Policy") == "no-referrer"
    conn.close()


@pytest.mark.parametrize("path", ["/../pyproject.toml", "/web/../../etc/passwd", "/sub/dir.css"])
def test_static_path_traversal_blocked(server, path: str) -> None:
    client, _ = server
    assert client.get(path, token=None)[0] == 404


def test_scan_path_must_be_within_allowed_roots(server, tmp_path: Path) -> None:
    client, _ = server
    outside = tmp_path.parent / "outside-root"
    outside.mkdir(exist_ok=True)
    status, body = client.post("/api/scans", body={"path": str(outside)})
    assert status == 400
    assert "許可されたルート" in body["error"]


def test_snippet_cannot_escape_target(server, project: Path) -> None:
    client, _ = server
    status, body = client.get(
        f"/api/snippet?target={project}&file=../../../etc/passwd&line=1")
    assert status == 400
    assert "外は読めません" in body["error"]


# ---------------- エンドポイント ----------------
def test_state_endpoint(server) -> None:
    client, _ = server
    status, body = client.get("/api/state")
    assert status == 200
    assert body["version"]
    assert body["osv_enabled"] is False


def test_rules_endpoint_lists_rule_ids(server) -> None:
    client, _ = server
    status, body = client.get("/api/rules")
    assert status == 200
    assert "code.os_system" in body["rules"]


def test_unknown_endpoint_404(server) -> None:
    client, _ = server
    assert client.get("/api/nope")[0] == 404


def test_scan_requires_path(server) -> None:
    client, _ = server
    status, body = client.post("/api/scans", body={})
    assert status == 400
    assert "path" in body["error"]


def test_malformed_json_body(server) -> None:
    client, _ = server
    conn = HTTPConnection("127.0.0.1", client.port, timeout=10)
    conn.request("POST", "/api/scans", body=b"{not json",
                 headers={"Host": f"127.0.0.1:{client.port}",
                          "X-Securia-Token": client.token,
                          "Content-Type": "application/json"})
    response = conn.getresponse()
    response.read()
    assert response.status == 400
    conn.close()


def test_full_scan_flow(server, project: Path) -> None:
    client, _ = server
    status, job = client.post("/api/scans", body={"path": str(project)})
    assert status == 202
    assert job["state"] == "running"

    finished = client.wait_for_job(job["job_id"])
    assert finished["state"] == "done"

    result = finished["result"]
    rules = {f["rule_id"] for f in result["findings"]}
    assert "secret.aws_access_key" in rules
    assert result["diff"]["has_baseline"] is False
    assert result["scan_id"]

    # 2回目は前回との比較が付く
    _, job2 = client.post("/api/scans", body={"path": str(project)})
    second = client.wait_for_job(job2["job_id"])
    assert second["result"]["diff"]["has_baseline"] is True
    assert second["result"]["diff"]["new_count"] == 0


def test_stored_scan_can_be_reloaded(server, project: Path) -> None:
    client, _ = server
    _, job = client.post("/api/scans", body={"path": str(project)})
    finished = client.wait_for_job(job["job_id"])
    scan_id = finished["result"]["scan_id"]

    status, scan = client.get(f"/api/scans/{scan_id}")
    assert status == 200
    assert scan["target"] == str(project.resolve())
    assert scan["findings"]

    status, listing = client.get("/api/scans")
    assert status == 200
    assert listing["scans"][0]["id"] == scan_id


def test_scan_id_must_be_numeric(server) -> None:
    client, _ = server
    assert client.get("/api/scans/abc")[0] == 400
    assert client.get("/api/scans/999999")[0] == 404


def test_snippet_returns_context_lines(server, project: Path) -> None:
    client, _ = server
    status, body = client.get(f"/api/snippet?target={project}&file=app.py&line=2")
    assert status == 200
    assert [line["line"] for line in body["lines"]] == [1, 2]
    assert body["lines"][1]["target"] is True


def test_suppression_endpoints(server, project: Path) -> None:
    client, _ = server
    _, job = client.post("/api/scans", body={"path": str(project)})
    finished = client.wait_for_job(job["job_id"])
    target = finished["target"]
    fingerprint = finished["result"]["findings"][0]["fingerprint"]

    status, _ = client.post("/api/suppressions", body={
        "target": target, "fingerprint": fingerprint, "reason": "誤検知", "rule_id": "code.x"})
    assert status == 201

    _, listing = client.get(f"/api/suppressions?target={target}")
    assert listing["suppressions"][0]["fingerprint"] == fingerprint

    # 次のスキャンでは抑制済みとして扱われる
    _, job2 = client.post("/api/scans", body={"path": str(project)})
    second = client.wait_for_job(job2["job_id"])
    suppressed = [f for f in second["result"]["findings"] if f["suppressed"]]
    assert len(suppressed) == 1

    status, _ = client.delete(f"/api/suppressions/{fingerprint}?target={target}")
    assert status == 200
    _, listing = client.get(f"/api/suppressions?target={target}")
    assert listing["suppressions"] == []


def test_suppression_requires_target(server) -> None:
    client, _ = server
    assert client.post("/api/suppressions", body={"fingerprint": "abc"})[0] == 400
    assert client.delete("/api/suppressions/abc")[0] == 400


def test_cancel_unknown_job(server) -> None:
    client, _ = server
    assert client.delete("/api/jobs/nope")[0] == 404


def test_cancel_finished_job_conflicts(server, project: Path) -> None:
    """存在しないジョブ (404) と、終わったジョブ (409) は区別する。"""
    client, _ = server
    _, job = client.post("/api/scans", body={"path": str(project)})
    client.wait_for_job(job["job_id"])
    status, body = client.delete(f"/api/jobs/{job['job_id']}")
    assert status == 409
    assert "done" in body["error"]


def test_job_events_stream(server, project: Path) -> None:
    client, _ = server
    _, job = client.post("/api/scans", body={"path": str(project)})

    conn = HTTPConnection("127.0.0.1", client.port, timeout=20)
    conn.request("GET", f"/api/jobs/{job['job_id']}/events",
                 headers={"Host": f"127.0.0.1:{client.port}", "X-Securia-Token": client.token})
    response = conn.getresponse()
    assert response.status == 200
    assert response.getheader("Content-Type").startswith("text/event-stream")

    text = response.read().decode("utf-8")
    conn.close()

    events = [json.loads(line[6:]) for line in text.splitlines() if line.startswith("data: ")]
    assert events[0]["type"] == "state"
    # スキャンが購読開始より先に終わることもある。その場合は最初のスナップショットが
    # 終了状態を持ち、それだけで閉じる。どちらの経路でも「終端まで届く」ことを見る。
    last = events[-1]
    assert last["type"] in ("done", "cancelled", "error") or last.get("state") == "done"

    # 終わったあとで問い合わせれば必ず結果が取れている
    assert client.wait_for_job(job["job_id"])["state"] == "done"


def test_events_for_finished_job_do_not_hang(server, project: Path) -> None:
    """購読開始時に既に終わっていても、状態を1つ返して閉じる。"""
    client, _ = server
    _, job = client.post("/api/scans", body={"path": str(project)})
    client.wait_for_job(job["job_id"])

    conn = HTTPConnection("127.0.0.1", client.port, timeout=10)
    conn.request("GET", f"/api/jobs/{job['job_id']}/events",
                 headers={"Host": f"127.0.0.1:{client.port}", "X-Securia-Token": client.token})
    text = conn.getresponse().read().decode("utf-8")
    conn.close()

    events = [json.loads(line[6:]) for line in text.splitlines() if line.startswith("data: ")]
    assert len(events) == 1
    assert events[0]["state"] == "done"
