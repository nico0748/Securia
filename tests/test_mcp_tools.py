"""MCP のツール群。"""
from __future__ import annotations

import json
from pathlib import Path

import pytest

from securia.config import Config, ScanConfig
from securia.mcp.server import LATEST_PROTOCOL_VERSION, McpServer
from securia.store import Store

INIT = {
    "jsonrpc": "2.0", "id": 1, "method": "initialize",
    "params": {"protocolVersion": LATEST_PROTOCOL_VERSION, "capabilities": {},
               "clientInfo": {"name": "test", "version": "1"}},
}


@pytest.fixture
def project(tmp_path: Path) -> Path:
    root = tmp_path / "project"
    (root / "src").mkdir(parents=True)
    (root / "src" / "app.py").write_text(
        'import os\n'
        'AWS_KEY = "AKIAIOSFODNN7EXAMPLE"\n'
        'os.system(cmd)\n'
        'h = md5(x)\n',
        encoding="utf-8")
    (root / "package.json").write_text(
        json.dumps({"dependencies": {"lodash": "4.17.20"}}), encoding="utf-8")
    (root / "Dockerfile").write_text("FROM python:latest\n", encoding="utf-8")
    return root


class Harness:
    """MCP サーバーをツール呼び出し単位で扱う薄いラッパ。"""

    def __init__(self, server: McpServer) -> None:
        self.server = server
        self._next_id = 10

    def call(self, name: str, **arguments) -> tuple[str, bool]:
        self._next_id += 1
        response = self.server.handle({
            "jsonrpc": "2.0", "id": self._next_id, "method": "tools/call",
            "params": {"name": name, "arguments": arguments},
        })
        result = response["result"]
        return result["content"][0]["text"], result["isError"]

    def ok(self, name: str, **arguments) -> str:
        text, is_error = self.call(name, **arguments)
        assert not is_error, f"{name} が失敗しました: {text}"
        return text

    def fails(self, name: str, **arguments) -> str:
        text, is_error = self.call(name, **arguments)
        assert is_error, f"{name} は失敗するはずでした: {text}"
        return text

    def request(self, method: str, params: dict | None = None) -> dict:
        self._next_id += 1
        return self.server.handle({
            "jsonrpc": "2.0", "id": self._next_id, "method": method, "params": params or {},
        })


@pytest.fixture
def mcp(tmp_path: Path) -> Harness:
    cfg = Config()
    cfg.scan = ScanConfig(allowed_roots=[str(tmp_path)])
    cfg.osv.enabled = False
    store = Store(tmp_path / "mcp.db")
    server = McpServer(cfg, store)
    server.handle(INIT)
    yield Harness(server)
    store.close()


def fingerprint_of(text: str, rule_id: str) -> str:
    """一覧テキストから指定ルールの fingerprint を取り出す。"""
    for line in text.splitlines():
        if rule_id in line and "[" in line:
            return line.split("[")[1].split("]")[0]
    raise AssertionError(f"{rule_id} が見つかりません:\n{text}")


# ---------------- tools/list ----------------
def test_tools_list_shape(mcp: Harness) -> None:
    tools = mcp.request("tools/list")["result"]["tools"]
    names = {t["name"] for t in tools}
    assert names == {
        "securia_scan", "securia_list_findings", "securia_get_finding",
        "securia_list_components", "securia_scan_history", "securia_suppress",
        "securia_unsuppress", "securia_list_suppressions", "securia_list_rules",
    }
    for tool in tools:
        assert tool["description"]
        schema = tool["inputSchema"]
        assert schema["type"] == "object"
        assert schema["additionalProperties"] is False
        assert "properties" in schema


def test_state_changing_tools_are_not_marked_read_only(mcp: Harness) -> None:
    tools = {t["name"]: t for t in mcp.request("tools/list")["result"]["tools"]}
    assert tools["securia_scan"]["annotations"]["readOnlyHint"] is False
    assert tools["securia_suppress"]["annotations"]["readOnlyHint"] is False
    assert tools["securia_list_findings"]["annotations"]["readOnlyHint"] is True


def test_unknown_tool_is_a_tool_error_not_protocol_error(mcp: Harness) -> None:
    text = mcp.fails("securia_nope")
    assert "securia_scan" in text     # 使えるツールを案内する


# ---------------- scan ----------------
def test_scan_reports_summary_and_findings(mcp: Harness, project: Path) -> None:
    text = mcp.ok("securia_scan", path=str(project), offline=True)
    assert "secret.aws_access_key" in text
    assert "code.os_system" in text
    assert "docker.latest_tag" in text
    assert "scan_id: 1" in text
    assert "初回スキャン" in text
    assert "OSV 照合は無効" in text


def test_scan_min_severity_filters(mcp: Harness, project: Path) -> None:
    text = mcp.ok("securia_scan", path=str(project), offline=True, min_severity="CRITICAL")
    assert "secret.aws_access_key" in text
    assert "docker.latest_tag" not in text      # LOW は出ない


def test_scan_limit_points_to_followup_tool(mcp: Harness, project: Path) -> None:
    text = mcp.ok("securia_scan", path=str(project), offline=True, limit=1)
    assert "securia_list_findings" in text
    assert "残り" in text


def test_scan_second_run_reports_diff(mcp: Harness, project: Path) -> None:
    mcp.ok("securia_scan", path=str(project), offline=True)
    text = mcp.ok("securia_scan", path=str(project), offline=True)
    assert "前回比: 新規 0" in text


def test_scan_detects_newly_added_problem(mcp: Harness, project: Path) -> None:
    mcp.ok("securia_scan", path=str(project), offline=True)
    (project / "src" / "extra.py").write_text("eval(untrusted)\n", encoding="utf-8")
    text = mcp.ok("securia_scan", path=str(project), offline=True)
    assert "前回比: 新規 1" in text


def test_scan_outside_allowed_roots_is_refused(mcp: Harness, tmp_path: Path) -> None:
    outside = tmp_path.parent / "mcp-outside"
    outside.mkdir(exist_ok=True)
    assert "許可されたルート" in mcp.fails("securia_scan", path=str(outside))


def test_scan_requires_path(mcp: Harness) -> None:
    assert "path" in mcp.fails("securia_scan")


def test_scan_rejects_bad_severity(mcp: Harness, project: Path) -> None:
    assert "min_severity" in mcp.fails("securia_scan", path=str(project), min_severity="SEVERE")


def test_scan_without_save_leaves_no_history(mcp: Harness, project: Path) -> None:
    mcp.ok("securia_scan", path=str(project), offline=True, save=False)
    assert "履歴はありません" in mcp.ok("securia_scan_history")


# ---------------- list_findings ----------------
def test_list_findings_uses_latest_scan_by_default(mcp: Harness, project: Path) -> None:
    mcp.ok("securia_scan", path=str(project), offline=True)
    assert "scan_id=1" in mcp.ok("securia_list_findings")


def test_list_findings_filters(mcp: Harness, project: Path) -> None:
    mcp.ok("securia_scan", path=str(project), offline=True)

    by_category = mcp.ok("securia_list_findings", category="config")
    assert "docker.latest_tag" in by_category
    assert "code.os_system" not in by_category

    by_rule = mcp.ok("securia_list_findings", rule_id="secret.*")
    assert "secret.aws_access_key" in by_rule
    assert "code.os_system" not in by_rule

    by_file = mcp.ok("securia_list_findings", file="Dockerfile")
    assert "docker.latest_tag" in by_file
    assert "src/app.py" not in by_file

    by_severity = mcp.ok("securia_list_findings", min_severity="HIGH")
    assert "code.weak_hash" not in by_severity


def test_list_findings_pagination(mcp: Harness, project: Path) -> None:
    mcp.ok("securia_scan", path=str(project), offline=True)
    page = mcp.ok("securia_list_findings", limit=2)
    assert "offset=2" in page
    assert "続きは" in page


def test_list_findings_no_match(mcp: Harness, project: Path) -> None:
    mcp.ok("securia_scan", path=str(project), offline=True)
    assert "一致する検出はありません" in mcp.ok("securia_list_findings", rule_id="nothing.*")


def test_list_findings_unknown_scan(mcp: Harness) -> None:
    assert "見つかりません" in mcp.fails("securia_list_findings", scan_id=999)


def test_list_findings_without_any_scan(mcp: Harness) -> None:
    assert "securia_scan" in mcp.fails("securia_list_findings")


def test_list_findings_rejects_bad_category(mcp: Harness, project: Path) -> None:
    mcp.ok("securia_scan", path=str(project), offline=True)
    assert "category" in mcp.fails("securia_list_findings", category="bogus")


# ---------------- get_finding ----------------
def test_get_finding_includes_source_snippet(mcp: Harness, project: Path) -> None:
    listing = mcp.ok("securia_scan", path=str(project), offline=True)
    fp = fingerprint_of(listing, "secret.aws_access_key")

    text = mcp.ok("securia_get_finding", fingerprint=fp)
    assert "AWSアクセスキーIDのハードコード" in text
    assert "該当コード" in text
    assert "AKIAIOSFODNN7EXAMPLE" in text     # ファイルから読む（DB には無い）
    assert "> 2 |" in text                    # 該当行に印
    assert "securia_suppress" in text         # 次の操作を案内


def test_get_finding_context_lines_zero_omits_snippet(mcp: Harness, project: Path) -> None:
    listing = mcp.ok("securia_scan", path=str(project), offline=True)
    fp = fingerprint_of(listing, "secret.aws_access_key")
    assert "該当コード" not in mcp.ok("securia_get_finding", fingerprint=fp, context_lines=0)


def test_get_finding_handles_deleted_file(mcp: Harness, project: Path) -> None:
    listing = mcp.ok("securia_scan", path=str(project), offline=True)
    fp = fingerprint_of(listing, "secret.aws_access_key")
    (project / "src" / "app.py").unlink()
    assert "存在しません" in mcp.ok("securia_get_finding", fingerprint=fp)


def test_get_finding_unknown_fingerprint(mcp: Harness, project: Path) -> None:
    mcp.ok("securia_scan", path=str(project), offline=True)
    assert "見つかりません" in mcp.fails("securia_get_finding", fingerprint="0000000000000000")


# ---------------- components ----------------
def test_list_components(mcp: Harness, project: Path) -> None:
    mcp.ok("securia_scan", path=str(project), offline=True)
    text = mcp.ok("securia_list_components")
    assert "lodash" in text
    assert "npm" in text


def test_list_components_filters(mcp: Harness, project: Path) -> None:
    mcp.ok("securia_scan", path=str(project), offline=True)
    assert "一致するコンポーネント" in mcp.ok("securia_list_components", vulnerable_only=True)
    assert "lodash" in mcp.ok("securia_list_components", ecosystem="npm")
    assert "一致するコンポーネント" in mcp.ok("securia_list_components", ecosystem="PyPI")


# ---------------- 履歴 ----------------
def test_scan_history(mcp: Harness, project: Path) -> None:
    assert "履歴はありません" in mcp.ok("securia_scan_history")
    mcp.ok("securia_scan", path=str(project), offline=True)
    mcp.ok("securia_scan", path=str(project), offline=True)
    text = mcp.ok("securia_scan_history")
    assert "scan_id=2" in text
    assert "scan_id=1" in text


# ---------------- 抑制 ----------------
def test_suppression_round_trip(mcp: Harness, project: Path) -> None:
    listing = mcp.ok("securia_scan", path=str(project), offline=True)
    fp = fingerprint_of(listing, "code.weak_hash")

    assert "抑制しました" in mcp.ok("securia_suppress", fingerprint=fp, reason="テスト用")
    assert fp in mcp.ok("securia_list_suppressions")

    after = mcp.ok("securia_scan", path=str(project), offline=True)
    assert "抑制済み 1 件" in after
    assert "code.weak_hash" not in after

    assert "解除しました" in mcp.ok("securia_unsuppress", fingerprint=fp)
    assert "抑制された検出はありません" in mcp.ok("securia_list_suppressions")

    restored = mcp.ok("securia_scan", path=str(project), offline=True)
    assert "code.weak_hash" in restored


def test_suppress_unknown_fingerprint(mcp: Harness, project: Path) -> None:
    mcp.ok("securia_scan", path=str(project), offline=True)
    assert "見つかりません" in mcp.fails("securia_suppress", fingerprint="0000000000000000")


def test_unsuppress_when_not_suppressed(mcp: Harness, project: Path) -> None:
    mcp.ok("securia_scan", path=str(project), offline=True)
    assert "抑制はありません" in mcp.fails("securia_unsuppress", fingerprint="0000000000000000")


def test_suppressed_findings_visible_on_request(mcp: Harness, project: Path) -> None:
    listing = mcp.ok("securia_scan", path=str(project), offline=True)
    fp = fingerprint_of(listing, "code.weak_hash")
    mcp.ok("securia_suppress", fingerprint=fp)
    mcp.ok("securia_scan", path=str(project), offline=True)

    assert "code.weak_hash" not in mcp.ok("securia_list_findings")
    shown = mcp.ok("securia_list_findings", include_suppressed=True)
    assert "code.weak_hash" in shown
    assert "抑制済み" in shown


# ---------------- ルール ----------------
def test_list_rules(mcp: Harness) -> None:
    text = mcp.ok("securia_list_rules")
    assert "code.os_system" in text
    assert "docker.no_user" in text


def test_list_rules_pattern(mcp: Harness) -> None:
    text = mcp.ok("securia_list_rules", pattern="secret.*")
    assert "secret.aws_access_key" in text
    assert "code.os_system" not in text
    assert "一致するルールはありません" in mcp.ok("securia_list_rules", pattern="zzz.*")


def test_list_rules_marks_configured_rules(tmp_path: Path) -> None:
    cfg = Config()
    cfg.scan = ScanConfig(allowed_roots=[str(tmp_path)])
    cfg.osv.enabled = False
    cfg.rules.disabled = ["code.weak_hash"]
    cfg.rules.severity = {"code.os_system": "LOW"}

    store = Store(tmp_path / "m.db")
    server = McpServer(cfg, store)
    server.handle(INIT)
    text = Harness(server).ok("securia_list_rules")
    store.close()

    assert "code.weak_hash  (無効)" in text
    assert "code.os_system  (重要度上書き=LOW)" in text


# ---------------- リソース ----------------
def test_resources_list_includes_rules_and_scans(mcp: Harness, project: Path) -> None:
    mcp.ok("securia_scan", path=str(project), offline=True)
    resources = mcp.request("resources/list")["result"]["resources"]
    uris = {r["uri"] for r in resources}
    assert "securia://rules" in uris
    assert "securia://scans/1" in uris


def test_resource_templates(mcp: Harness) -> None:
    templates = mcp.request("resources/templates/list")["result"]["resourceTemplates"]
    assert templates[0]["uriTemplate"] == "securia://scans/{scan_id}"


def test_read_rules_resource(mcp: Harness) -> None:
    contents = mcp.request("resources/read", {"uri": "securia://rules"})["result"]["contents"][0]
    assert contents["mimeType"] == "text/plain"
    assert "code.os_system" in contents["text"]


def test_read_scan_resource(mcp: Harness, project: Path) -> None:
    mcp.ok("securia_scan", path=str(project), offline=True)
    contents = mcp.request("resources/read", {"uri": "securia://scans/1"})["result"]["contents"][0]
    payload = json.loads(contents["text"])
    assert payload["id"] == 1
    assert payload["findings"]
    assert payload["components"]
    assert "evidence" not in payload["findings"][0]      # 生のコードは出さない


def test_read_unknown_resource(mcp: Harness) -> None:
    assert "error" in mcp.request("resources/read", {"uri": "securia://nope"})


def test_read_missing_scan_resource(mcp: Harness) -> None:
    assert "error" in mcp.request("resources/read", {"uri": "securia://scans/999"})
