"""Finding の同一性（fingerprint）と重要度ユーティリティ。"""
from __future__ import annotations

import pytest

from securia.models import (
    Finding,
    assign_occurrences,
    normalize_severity,
    severity_rank,
    worst_severity,
)


def make(**kw) -> Finding:
    base = dict(category="static", severity="HIGH", title="t", rule_id="code.x",
                file="a.py", line=10, evidence="os.system(cmd)")
    base.update(kw)
    f = Finding(**base)
    f.compute_fingerprint()
    return f


# ---------------- fingerprint ----------------
def test_fingerprint_ignores_line_number() -> None:
    """行がずれただけで別物にならないことが差分機能の前提。"""
    assert make(line=10).fingerprint == make(line=250).fingerprint


def test_fingerprint_ignores_surrounding_whitespace() -> None:
    assert make(evidence="  os.system(cmd)  ").fingerprint == make(evidence="os.system(cmd)").fingerprint
    assert make(evidence="os.system(  cmd )").fingerprint != make(evidence="os.system(cmd)").fingerprint


def test_fingerprint_changes_with_content() -> None:
    assert make(evidence="os.system(a)").fingerprint != make(evidence="os.system(b)").fingerprint


def test_fingerprint_changes_with_file() -> None:
    assert make(file="a.py").fingerprint != make(file="b.py").fingerprint


def test_fingerprint_changes_with_rule() -> None:
    assert make(rule_id="code.x").fingerprint != make(rule_id="code.y").fingerprint


def test_fingerprint_is_stable_across_runs() -> None:
    assert make().fingerprint == make().fingerprint


def test_dependency_fingerprint_includes_version() -> None:
    """依存は版が上がれば別の検出。静的解析では版は関係しない。"""
    a = make(category="dependency", package="lodash", version="4.17.20", evidence="CVE-1")
    b = make(category="dependency", package="lodash", version="4.17.21", evidence="CVE-1")
    assert a.fingerprint != b.fingerprint

    c = make(category="static", version="1.0")
    d = make(category="static", version="2.0")
    assert c.fingerprint == d.fingerprint


def test_severity_is_normalised_on_fingerprint() -> None:
    assert make(severity="high").severity == "HIGH"
    assert make(severity="bogus").severity == "INFO"


# ---------------- 出力 ----------------
def test_to_dict_excludes_raw_evidence() -> None:
    """evidence には秘密情報そのものが入りうる。外に出してはいけない。"""
    d = make(evidence='AWS_KEY = "AKIAIOSFODNN7EXAMPLE"').to_dict()
    assert "evidence" not in d
    assert "AKIA" not in repr(d)
    assert d["uid"]
    assert d["fingerprint"]


# ---------------- 重複の連番 ----------------
def test_assign_occurrences_numbers_duplicates() -> None:
    findings = [make(line=1), make(line=5), make(file="b.py")]
    assign_occurrences(findings)
    assert [f.occurrence for f in findings] == [0, 1, 0]
    assert len({f.uid for f in findings}) == 3


def test_assign_occurrences_resets_per_fingerprint() -> None:
    findings = [make(file="a.py"), make(file="b.py"), make(file="a.py")]
    assign_occurrences(findings)
    assert [f.occurrence for f in findings] == [0, 0, 1]


# ---------------- 重要度 ----------------
@pytest.mark.parametrize(
    ("sevs", "expected"),
    [(["LOW", "CRITICAL", "HIGH"], "CRITICAL"), (["LOW", "INFO"], "LOW"),
     ([], "INFO"), (["medium", "low"], "MEDIUM"), (["bogus"], "INFO")],
)
def test_worst_severity(sevs: list[str], expected: str) -> None:
    assert worst_severity(sevs) == expected


def test_severity_rank_ordering() -> None:
    ranks = [severity_rank(s) for s in ("CRITICAL", "HIGH", "MEDIUM", "LOW", "INFO")]
    assert ranks == sorted(ranks, reverse=True)
    assert severity_rank("unknown") == 0
    assert severity_rank("") == 0


@pytest.mark.parametrize(("raw", "expected"), [("high", "HIGH"), ("", "INFO"), ("XX", "INFO")])
def test_normalize_severity(raw: str, expected: str) -> None:
    assert normalize_severity(raw) == expected
