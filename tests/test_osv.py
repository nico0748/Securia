"""OSV クライアント。ネットワークには出さず、post/get を差し替えて検証する。"""
from __future__ import annotations

import pytest

from securia.config import OsvConfig
from securia.models import Component, Finding
from securia.osv import (
    STATUS_DISABLED,
    STATUS_OFFLINE,
    STATUS_OK,
    OsvClient,
    canonical_id,
    derive_severity,
    fixed_version,
    merge_advisories,
    pick_fixed_version,
)


# ---------------- 重要度の導出 ----------------
def test_database_specific_label_wins() -> None:
    vuln = {
        "database_specific": {"severity": "MODERATE"},
        "severity": [{"type": "CVSS_V3", "score": "CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:H"}],
    }
    assert derive_severity(vuln) == "MEDIUM"


def test_affected_label_used_when_toplevel_missing() -> None:
    vuln = {"affected": [{"database_specific": {"severity": "HIGH"}}]}
    assert derive_severity(vuln) == "HIGH"


def test_picks_worst_of_multiple_cvss_vectors() -> None:
    """複数の CVSS ベクタがあるとき最も深刻なものを採る。

    以前は条件式が壊れていて「最後のベクタ」が勝っていた。並び順に依らず
    CRITICAL になることを確かめる。
    """
    critical = "CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:H"   # 9.8
    low = "CVSS:3.1/AV:L/AC:H/PR:H/UI:R/S:U/C:L/I:N/A:N"        # LOW 相当

    worst_last = {"severity": [{"type": "CVSS_V3", "score": low},
                               {"type": "CVSS_V3", "score": critical}]}
    worst_first = {"severity": [{"type": "CVSS_V3", "score": critical},
                                {"type": "CVSS_V3", "score": low}]}

    assert derive_severity(worst_last) == "CRITICAL"
    assert derive_severity(worst_first) == "CRITICAL"


def test_defaults_to_medium_without_any_signal() -> None:
    assert derive_severity({}) == "MEDIUM"


def test_ignores_non_cvss_severity_entries() -> None:
    vuln = {"severity": [{"type": "SOMETHING_ELSE", "score": "9.9"}]}
    assert derive_severity(vuln) == "MEDIUM"


# ---------------- 修正バージョン ----------------
def test_fixed_version_matches_package_case_insensitively() -> None:
    vuln = {"affected": [{
        "package": {"name": "LoDash"},
        "ranges": [{"events": [{"introduced": "0"}, {"fixed": "4.17.21"}]}],
    }]}
    assert fixed_version(vuln, "lodash") == "4.17.21"


def test_fixed_version_skips_other_packages() -> None:
    vuln = {"affected": [{
        "package": {"name": "other"},
        "ranges": [{"events": [{"fixed": "1.0.0"}]}],
    }]}
    assert fixed_version(vuln, "lodash") == ""


@pytest.mark.parametrize(
    ("candidates", "expected"),
    [
        (["4.18.0", "4.17.21"], "4.17.21"),                       # 最小の版を選ぶ
        (["70f906c51ce49c485f1d355703e9cc3386b1cc2b", "2.3.2"], "2.3.2"),  # git SHA は避ける
        (["70f906c51ce49c485f1d355703e9cc3386b1cc2b"], "70f906c51ce49c485f1d355703e9cc3386b1cc2b"),
        (["", ""], ""),
        (["v1.2.0", "v1.10.0"], "v1.2.0"),                        # 数値として比較する
    ],
)
def test_pick_fixed_version(candidates: list[str], expected: str) -> None:
    assert pick_fixed_version(candidates) == expected


# ---------------- 勧告の統合 ----------------
def test_canonical_id_prefers_cve() -> None:
    assert canonical_id("GHSA-xxxx", {"aliases": ["GHSA-yyyy", "CVE-2021-23337"]}) == "CVE-2021-23337"
    assert canonical_id("GHSA-xxxx", {"aliases": []}) == "GHSA-xxxx"
    assert canonical_id("PYSEC-2023-62", {}) == "PYSEC-2023-62"


def _finding(rule_id: str, severity: str, fixed: str, refs: list[str], desc: str = "d") -> Finding:
    f = Finding(category="dependency", severity=severity, title="t", rule_id=rule_id,
                description=desc, package="lodash", version="4.17.20",
                references=list(refs), fixed_version=fixed)
    f.compute_fingerprint()
    return f


def test_merge_advisories_collapses_same_cve() -> None:
    """OSV は同じ CVE を GHSA と PYSEC で二重に返すことがある。1件に畳む。"""
    group = [
        _finding("CVE-2023-30861", "MEDIUM", "70f906c51ce49c485f1d355703e9cc3386b1cc2b", ["a"], "短い"),
        _finding("CVE-2023-30861", "HIGH", "2.3.2", ["b"], "こちらの方が説明が長い"),
    ]
    merged = merge_advisories(group)

    assert len(merged) == 1
    assert merged[0].severity == "HIGH"                  # 保守的に最悪値
    assert merged[0].fixed_version == "2.3.2"            # git SHA ではなく版数
    assert merged[0].references == ["b", "a"] or merged[0].references == ["a", "b"]
    assert set(merged[0].references) == {"a", "b"}       # 参照は統合
    assert merged[0].description == "こちらの方が説明が長い"
    assert "2.3.2" in merged[0].recommendation


def test_merge_advisories_keeps_distinct_cves() -> None:
    group = [_finding("CVE-1", "LOW", "1.0", []), _finding("CVE-2", "HIGH", "2.0", [])]
    assert len(merge_advisories(group)) == 2


def test_merge_advisories_preserves_order() -> None:
    group = [_finding("CVE-2", "LOW", "", []), _finding("CVE-1", "LOW", "", [])]
    assert [f.rule_id for f in merge_advisories(group)] == ["CVE-2", "CVE-1"]


# ---------------- クライアント ----------------
def _components() -> list[Component]:
    return [Component(name="lodash", version="4.17.20", ecosystem="npm", file="package.json")]


def test_disabled_client_short_circuits() -> None:
    client = OsvClient(OsvConfig(enabled=False))
    findings, status = client.enrich(_components())
    assert (findings, status) == ([], STATUS_DISABLED)


def test_empty_components_is_ok() -> None:
    client = OsvClient(OsvConfig())
    assert client.enrich([]) == ([], STATUS_OK)


def test_network_failure_reports_offline() -> None:
    def failing_post(url, payload, timeout):
        raise OSError("no network")

    client = OsvClient(OsvConfig(), post=failing_post)
    findings, status = client.enrich(_components())
    assert (findings, status) == ([], STATUS_OFFLINE)


def test_enrich_builds_findings_and_updates_component() -> None:
    def fake_post(url, payload, timeout):
        return {"results": [{"vulns": [{"id": "GHSA-1"}, {"id": "PYSEC-1"}]}]}

    def fake_get(url, timeout):
        vuln_id = url.rsplit("/", 1)[-1]
        return {
            "id": vuln_id,
            "aliases": ["CVE-2021-23337"],           # 両方とも同じ CVE
            "summary": f"summary of {vuln_id}",
            "database_specific": {"severity": "HIGH"},
            "affected": [{"package": {"name": "lodash"},
                          "ranges": [{"events": [{"fixed": "4.17.21"}]}]}],
            "references": [{"url": f"https://example.test/{vuln_id}"}],
        }

    comps = _components()
    client = OsvClient(OsvConfig(), post=fake_post, get=fake_get)
    findings, status = client.enrich(comps)

    assert status == STATUS_OK
    assert len(findings) == 1                      # 2レコードが1件に統合される
    assert findings[0].rule_id == "CVE-2021-23337"
    assert findings[0].severity == "HIGH"
    assert findings[0].fixed_version == "4.17.21"
    assert comps[0].vuln_count == 1
    assert comps[0].max_severity == "HIGH"


def test_enrich_follows_pagination() -> None:
    calls: list[dict] = []

    def fake_post(url, payload, timeout):
        calls.append(payload)
        if "page_token" in payload["queries"][0]:
            return {"results": [{"vulns": [{"id": "GHSA-2"}]}]}
        return {"results": [{"vulns": [{"id": "GHSA-1"}], "next_page_token": "tok"}]}

    def fake_get(url, timeout):
        vuln_id = url.rsplit("/", 1)[-1]
        return {"id": vuln_id, "summary": vuln_id, "database_specific": {"severity": "LOW"}}

    client = OsvClient(OsvConfig(), post=fake_post, get=fake_get)
    findings, status = client.enrich(_components())

    assert status == STATUS_OK
    assert len(calls) == 2
    assert {f.rule_id for f in findings} == {"GHSA-1", "GHSA-2"}


def test_detail_fetch_failure_is_tolerated() -> None:
    def fake_post(url, payload, timeout):
        return {"results": [{"vulns": [{"id": "GHSA-1"}, {"id": "GHSA-2"}]}]}

    def flaky_get(url, timeout):
        if url.endswith("GHSA-1"):
            raise TimeoutError("slow")
        return {"id": "GHSA-2", "summary": "ok", "database_specific": {"severity": "LOW"}}

    client = OsvClient(OsvConfig(max_workers=2), post=fake_post, get=flaky_get)
    findings, status = client.enrich(_components())

    assert status == STATUS_OK
    assert [f.rule_id for f in findings] == ["GHSA-2"]


def test_cache_avoids_refetch(store) -> None:
    fetches: list[str] = []

    def fake_post(url, payload, timeout):
        return {"results": [{"vulns": [{"id": "GHSA-1"}]}]}

    def counting_get(url, timeout):
        fetches.append(url)
        return {"id": "GHSA-1", "summary": "s", "database_specific": {"severity": "LOW"}}

    cfg = OsvConfig()
    OsvClient(cfg, cache=store, post=fake_post, get=counting_get).enrich(_components())
    OsvClient(cfg, cache=store, post=fake_post, get=counting_get).enrich(_components())

    assert len(fetches) == 1  # 2回目はキャッシュから
