"""前回スキャンとの比較。

fingerprint の集合差で「新規」「修正済み」「継続」を出す。行番号を含まない
fingerprint を使っているので、コードが上下にずれただけでは新規にならない。

初回スキャンには比較対象が無い。このとき全件を「新規」にすると初回だけ
画面が真っ赤になって意味を成さないので、すべて「継続」として扱う。
"""
from __future__ import annotations

from dataclasses import dataclass, field

from .engine import ScanResult
from .models import Finding, severity_rank
from .store import Store

STATUS_NEW = "new"
STATUS_EXISTING = "existing"


@dataclass
class ScanDiff:
    previous_scan_id: int | None = None
    new_count: int = 0
    fixed_count: int = 0
    existing_count: int = 0
    fixed: list[Finding] = field(default_factory=list)

    @property
    def has_baseline(self) -> bool:
        return self.previous_scan_id is not None

    def to_dict(self) -> dict:
        return {
            "previous_scan_id": self.previous_scan_id,
            "has_baseline": self.has_baseline,
            "new_count": self.new_count,
            "fixed_count": self.fixed_count,
            "existing_count": self.existing_count,
            "fixed": [f.to_dict() for f in self.fixed],
        }


def mark_status(findings: list[Finding], previous_fingerprints: set[str]) -> None:
    """各 Finding に new / existing を設定する。"""
    for f in findings:
        f.status = STATUS_NEW if f.fingerprint not in previous_fingerprints else STATUS_EXISTING


def collect_fixed(previous_findings: list[Finding], current_fingerprints: set[str]) -> list[Finding]:
    """前回あって今回消えた検出を、fingerprint 単位で1件ずつ返す。"""
    out: list[Finding] = []
    seen: set[str] = set()
    for f in previous_findings:
        if f.fingerprint in current_fingerprints or f.fingerprint in seen:
            continue
        if f.suppressed:
            continue
        seen.add(f.fingerprint)
        out.append(f)
    out.sort(key=lambda f: (-severity_rank(f.severity), f.category, f.file, f.line))
    return out


def compare(store: Store, previous_scan_id: int | None, result: ScanResult) -> ScanDiff:
    """result の各 Finding に status を設定し、差分サマリを返す。

    result を保存する前に呼ぶこと（保存後だと自分自身が前回スキャンになる）。
    """
    if previous_scan_id is None:
        for f in result.findings:
            f.status = STATUS_EXISTING
        return ScanDiff(existing_count=len(result.active_findings))

    previous_fingerprints = store.fingerprints_of(previous_scan_id)
    mark_status(result.findings, previous_fingerprints)

    current_fingerprints = {f.fingerprint for f in result.findings}
    previous_findings = store.load_findings(previous_scan_id)
    fixed = collect_fixed(previous_findings, current_fingerprints)

    active = result.active_findings
    new_count = sum(1 for f in active if f.status == STATUS_NEW)
    return ScanDiff(
        previous_scan_id=previous_scan_id,
        new_count=new_count,
        fixed_count=len(fixed),
        existing_count=len(active) - new_count,
        fixed=fixed,
    )
