"""前回スキャンとの差分。"""
from __future__ import annotations

from securia import diff as diffmod
from securia.engine import ScanResult
from securia.models import Finding
from securia.store import Store


def make_finding(rule_id: str, file: str = "a.py", evidence: str | None = None) -> Finding:
    f = Finding(category="static", severity="HIGH", title=rule_id, rule_id=rule_id,
                file=file, line=1, evidence=evidence if evidence is not None else rule_id)
    f.compute_fingerprint()
    return f


def make_result(findings: list[Finding], target: str = "/proj") -> ScanResult:
    return ScanResult(target=target, scanned_at="2026-01-01T00:00:00+00:00", elapsed_sec=1.0,
                      osv_status="ok", total_files=1, findings=findings)


def test_first_scan_has_no_baseline(store: Store) -> None:
    """初回は比較対象が無い。全件を新規にすると意味を成さないので継続にする。"""
    result = make_result([make_finding("a"), make_finding("b")])
    d = diffmod.compare(store, None, result)

    assert d.has_baseline is False
    assert d.new_count == 0
    assert d.existing_count == 2
    assert all(f.status == "existing" for f in result.findings)


def test_detects_new_and_fixed(store: Store) -> None:
    previous = make_result([make_finding("keep"), make_finding("gone")])
    previous_id = store.save_scan(previous)

    current = make_result([make_finding("keep"), make_finding("added")])
    d = diffmod.compare(store, previous_id, current)

    assert d.has_baseline is True
    assert d.new_count == 1
    assert d.fixed_count == 1
    assert d.existing_count == 1
    assert d.fixed[0].rule_id == "gone"

    status = {f.rule_id: f.status for f in current.findings}
    assert status == {"keep": "existing", "added": "new"}


def test_line_shift_does_not_create_new(store: Store) -> None:
    """行番号が変わっただけの検出は新規にしない。"""
    previous = make_result([make_finding("a")])
    previous_id = store.save_scan(previous)

    shifted = make_finding("a")
    shifted.line = 500
    d = diffmod.compare(store, previous_id, make_result([shifted]))

    assert d.new_count == 0
    assert d.fixed_count == 0


def test_changed_content_counts_as_new(store: Store) -> None:
    previous_id = store.save_scan(make_result([make_finding("a", evidence="os.system(x)")]))
    current = make_result([make_finding("a", evidence="os.system(y)")])
    d = diffmod.compare(store, previous_id, current)

    assert d.new_count == 1
    assert d.fixed_count == 1


def test_suppressed_findings_excluded_from_counts(store: Store) -> None:
    previous_id = store.save_scan(make_result([make_finding("a")]))

    added = make_finding("added")
    added.suppressed = True
    current = make_result([make_finding("a"), added])
    d = diffmod.compare(store, previous_id, current)

    assert d.new_count == 0            # 抑制済みは新規に数えない
    assert d.existing_count == 1


def test_suppressed_findings_not_reported_as_fixed(store: Store) -> None:
    """抑制した検出が消えても「直った」ではない。"""
    suppressed = make_finding("noisy")
    suppressed.suppressed = True
    previous_id = store.save_scan(make_result([make_finding("a"), suppressed]))

    d = diffmod.compare(store, previous_id, make_result([make_finding("a")]))
    assert d.fixed_count == 0


def test_fixed_list_dedupes_by_fingerprint() -> None:
    dup_a, dup_b = make_finding("a"), make_finding("a")
    dup_b.occurrence = 1
    fixed = diffmod.collect_fixed([dup_a, dup_b, make_finding("b")], current_fingerprints=set())
    assert len(fixed) == 2


def test_fixed_list_sorted_by_severity() -> None:
    low, critical = make_finding("low"), make_finding("crit")
    low.severity = "LOW"
    critical.severity = "CRITICAL"
    fixed = diffmod.collect_fixed([low, critical], current_fingerprints=set())
    assert [f.severity for f in fixed] == ["CRITICAL", "LOW"]


def test_mark_status_directly() -> None:
    findings = [make_finding("a"), make_finding("b")]
    diffmod.mark_status(findings, {findings[0].fingerprint})
    assert [f.status for f in findings] == ["existing", "new"]


def test_diff_to_dict_is_serialisable(store: Store) -> None:
    previous_id = store.save_scan(make_result([make_finding("gone")]))
    d = diffmod.compare(store, previous_id, make_result([make_finding("new")]))
    payload = d.to_dict()

    assert payload["new_count"] == 1
    assert payload["has_baseline"] is True
    assert payload["fixed"][0]["rule_id"] == "gone"
    assert "evidence" not in payload["fixed"][0]
