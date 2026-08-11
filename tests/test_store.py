"""SQLite ストア。"""
from __future__ import annotations

import time
from pathlib import Path

from securia.engine import ScanResult
from securia.models import Component, Finding
from securia.store import Store


def make_finding(rule_id: str = "code.x", severity: str = "HIGH", file: str = "a.py") -> Finding:
    f = Finding(category="static", severity=severity, title=f"title {rule_id}", rule_id=rule_id,
                description="d", recommendation="r", file=file, line=3,
                references=["https://example.test/1"], evidence=f"evidence {rule_id} {file}")
    f.compute_fingerprint()
    return f


def make_result(findings: list[Finding], target: str = "/proj") -> ScanResult:
    return ScanResult(
        target=target, scanned_at="2026-01-01T00:00:00+00:00", elapsed_sec=1.5,
        osv_status="ok", total_files=42, findings=findings,
        components=[Component(name="lodash", version="4.17.20", ecosystem="npm",
                              file="package.json", vuln_count=2, max_severity="HIGH")],
    )


def test_save_and_reload_roundtrip(store: Store) -> None:
    finding = make_finding()
    scan_id = store.save_scan(make_result([finding]))

    scan = store.get_scan(scan_id)
    assert scan["target"] == "/proj"
    assert scan["total_files"] == 42
    assert scan["summary"]["total_findings"] == 1

    loaded = store.load_findings(scan_id)
    assert len(loaded) == 1
    assert loaded[0].fingerprint == finding.fingerprint
    assert loaded[0].title == finding.title
    assert loaded[0].references == ["https://example.test/1"]

    comps = store.load_components(scan_id)
    assert comps[0].name == "lodash"
    assert comps[0].vuln_count == 2


def test_raw_evidence_is_never_persisted(store: Store, tmp_path: Path) -> None:
    """DB が秘密情報の置き場にならないことを、ファイルの中身で直接確かめる。"""
    secret = "AKIAIOSFODNN7EXAMPLE"
    f = make_finding()
    f.evidence = f'AWS_KEY = "{secret}"'
    f.compute_fingerprint()
    store.save_scan(make_result([f]))
    store.close()

    raw = Path(store.path).read_bytes()
    assert secret.encode() not in raw


def test_history_is_ordered_newest_first(store: Store) -> None:
    for _ in range(3):
        store.save_scan(make_result([make_finding()]))
    ids = [s["id"] for s in store.list_scans()]
    assert ids == sorted(ids, reverse=True)


def test_list_scans_filters_by_target(store: Store) -> None:
    store.save_scan(make_result([make_finding()], target="/a"))
    store.save_scan(make_result([make_finding()], target="/b"))
    assert [s["target"] for s in store.list_scans("/a")] == ["/a"]


def test_latest_scan_id(store: Store) -> None:
    assert store.latest_scan_id("/proj") is None
    first = store.save_scan(make_result([make_finding()]))
    second = store.save_scan(make_result([make_finding()]))
    assert store.latest_scan_id("/proj") == second
    assert second > first


def test_fingerprints_of(store: Store) -> None:
    a, b = make_finding("code.a"), make_finding("code.b")
    scan_id = store.save_scan(make_result([a, b]))
    assert store.fingerprints_of(scan_id) == {a.fingerprint, b.fingerprint}


def test_duplicate_fingerprints_need_distinct_occurrences(store: Store) -> None:
    """同一 fingerprint が複数あっても主キー衝突しない。"""
    a, b = make_finding(), make_finding()
    assert a.fingerprint == b.fingerprint
    b.occurrence = 1
    scan_id = store.save_scan(make_result([a, b]))
    assert len(store.load_findings(scan_id)) == 2


def test_list_targets(store: Store) -> None:
    store.save_scan(make_result([make_finding()], target="/a"))
    store.save_scan(make_result([make_finding()], target="/b"))
    targets = {t["target"]: t for t in store.list_targets()}
    assert set(targets) == {"/a", "/b"}
    assert targets["/a"]["scan_count"] == 1
    assert targets["/a"]["last_scan"]["target"] == "/a"


def test_delete_scan_removes_children(store: Store) -> None:
    scan_id = store.save_scan(make_result([make_finding()]))
    assert store.delete_scan(scan_id) is True
    assert store.get_scan(scan_id) is None
    assert store.load_findings(scan_id) == []
    assert store.delete_scan(scan_id) is False


def test_prune_keeps_newest(store: Store) -> None:
    ids = [store.save_scan(make_result([make_finding()])) for _ in range(5)]
    assert store.prune("/proj", keep=2) == 3
    remaining = [s["id"] for s in store.list_scans("/proj")]
    assert remaining == ids[-2:][::-1]


# ---------------- 抑制 ----------------
def test_suppression_lifecycle(store: Store) -> None:
    f = make_finding()
    store.suppress("/proj", f, reason="誤検知")

    assert store.suppressed_fingerprints("/proj") == {f.fingerprint}
    rows = store.list_suppressions("/proj")
    assert rows[0]["reason"] == "誤検知"
    assert rows[0]["rule_id"] == "code.x"

    assert store.unsuppress("/proj", f.fingerprint) is True
    assert store.suppressed_fingerprints("/proj") == set()
    assert store.unsuppress("/proj", f.fingerprint) is False


def test_suppression_is_scoped_to_target(store: Store) -> None:
    """あるプロジェクトの抑制が、別プロジェクトの同じ検出まで消してはいけない。"""
    f = make_finding()
    store.suppress("/a", f)
    assert store.suppressed_fingerprints("/a") == {f.fingerprint}
    assert store.suppressed_fingerprints("/b") == set()


def test_suppress_twice_updates_reason(store: Store) -> None:
    f = make_finding()
    store.suppress("/proj", f, reason="最初")
    store.suppress("/proj", f, reason="あとで直す")
    rows = store.list_suppressions("/proj")
    assert len(rows) == 1
    assert rows[0]["reason"] == "あとで直す"


# ---------------- OSV キャッシュ ----------------
def test_vuln_cache_roundtrip(store: Store) -> None:
    store.put_vuln("GHSA-1", {"id": "GHSA-1", "summary": "s"})
    assert store.get_vuln("GHSA-1", ttl_days=7)["summary"] == "s"
    assert store.get_vuln("GHSA-missing", ttl_days=7) is None


def test_vuln_cache_expires(store: Store) -> None:
    store.put_vuln("GHSA-1", {"id": "GHSA-1"})
    # 8日前に取得したことにする
    with store._lock, store._conn:
        store._conn.execute("UPDATE osv_cache SET fetched_at = ?", (int(time.time()) - 8 * 86400,))
    assert store.get_vuln("GHSA-1", ttl_days=7) is None
    assert store.get_vuln("GHSA-1", ttl_days=30) is not None


def test_clear_vuln_cache(store: Store) -> None:
    store.put_vuln("GHSA-1", {"id": "GHSA-1"})
    assert store.clear_vuln_cache() == 1
    assert store.get_vuln("GHSA-1", ttl_days=7) is None


def test_reopening_existing_db_works(tmp_path: Path) -> None:
    path = tmp_path / "s.db"
    with Store(path) as s:
        scan_id = s.save_scan(make_result([make_finding()]))
    with Store(path) as s:
        assert s.get_scan(scan_id) is not None
