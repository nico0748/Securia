"""スキャンのオーケストレーション。

ツリーを1周だけ歩き、各ファイルの中身を1回だけ読んで、
静的解析・設定診断・依存関係の各スキャナへ配る。
"""
from __future__ import annotations

import time
from collections.abc import Callable
from dataclasses import dataclass, field
from datetime import UTC, datetime
from pathlib import Path
from threading import Event

from .config import Config
from .models import (
    CATEGORIES,
    SEVERITIES,
    Component,
    Finding,
    assign_occurrences,
    severity_rank,
)
from .osv import STATUS_DISABLED, OsvClient
from .scan import config_scan, dependency, static_code, walker

# progress(phase, current, total) — total <= 0 は件数不明を意味する
ProgressFn = Callable[[str, int, int], None]

_PROGRESS_EVERY = 200  # ファイル走査中の進捗通知間隔


@dataclass
class ScanResult:
    target: str
    scanned_at: str
    elapsed_sec: float
    osv_status: str
    total_files: int
    findings: list[Finding] = field(default_factory=list)
    components: list[Component] = field(default_factory=list)

    @property
    def active_findings(self) -> list[Finding]:
        """抑制されていない検出のみ。集計はすべてこちらを基準にする。"""
        return [f for f in self.findings if not f.suppressed]

    def summary(self) -> dict:
        active = self.active_findings
        severity_counts = dict.fromkeys(SEVERITIES, 0)
        category_counts = dict.fromkeys(CATEGORIES, 0)
        for f in active:
            severity_counts[f.severity] = severity_counts.get(f.severity, 0) + 1
            category_counts[f.category] = category_counts.get(f.category, 0) + 1

        ecosystems: dict[str, int] = {}
        for c in self.components:
            ecosystems[c.ecosystem] = ecosystems.get(c.ecosystem, 0) + 1

        return {
            "total_findings": len(active),
            "suppressed_findings": len(self.findings) - len(active),
            "severity_counts": severity_counts,
            "category_counts": category_counts,
            "total_files": self.total_files,
            "total_components": len(self.components),
            "vulnerable_components": sum(1 for c in self.components if c.vuln_count > 0),
            "ecosystems": ecosystems,
            "new_findings": sum(1 for f in active if f.status == "new"),
        }

    def to_dict(self) -> dict:
        return {
            "target": self.target,
            "scanned_at": self.scanned_at,
            "elapsed_sec": self.elapsed_sec,
            "osv_status": self.osv_status,
            "summary": self.summary(),
            "findings": [f.to_dict() for f in self.findings],
            "components": [
                c.to_dict()
                for c in sorted(
                    self.components,
                    key=lambda c: (-severity_rank(c.max_severity), -c.vuln_count, c.name),
                )
            ],
        }


def run_scan(
    root: Path,
    cfg: Config,
    *,
    osv_client: OsvClient | None = None,
    suppressed: set[str] | None = None,
    progress: ProgressFn | None = None,
    cancel: Event | None = None,
) -> ScanResult:
    """1回のスキャンを実行する。

    root は呼び出し側で paths.ensure_scannable() 済みであることを前提にする。
    """
    root = Path(root)
    started = time.monotonic()
    suppressed = suppressed or set()

    findings: list[Finding] = []
    manifests: list[dependency.ManifestResult] = []
    total_files = 0

    def emit(phase: str, current: int, total: int) -> None:
        if progress:
            progress(phase, current, total)

    emit("ファイルを走査中", 0, 0)
    for entry in walker.walk(root, cfg.scan, cancel):
        total_files += 1

        needs_dependency = dependency.applies_to(entry)
        needs_static = static_code.applies_to(entry)
        needs_config = config_scan.applies_to(entry)

        if needs_dependency or needs_static or needs_config:
            text = walker.read_text(entry, cfg.scan.max_file_bytes)
            if text:
                if needs_dependency:
                    result = dependency.collect_from_file(entry, text)
                    if result is not None:
                        manifests.append(result)
                if needs_static:
                    findings.extend(static_code.scan_file(entry, text, cfg.rules))
                if needs_config:
                    findings.extend(config_scan.scan_file(entry, text, cfg.rules))

        if total_files % _PROGRESS_EVERY == 0:
            emit("ファイルを走査中", total_files, 0)

    emit("ファイルを走査中", total_files, total_files)

    components = dependency.resolve(manifests)

    if osv_client is None:
        osv_status = STATUS_DISABLED
    else:
        emit("依存関係を OSV と照合中", 0, len(components))
        dep_findings, osv_status = osv_client.enrich(components, progress=progress, cancel=cancel)
        findings.extend(dep_findings)

    # 重要度順 → カテゴリ → ファイル → 行。順序を固定しないと occurrence が揺れる。
    findings.sort(key=lambda f: (-severity_rank(f.severity), f.category, f.file, f.line, f.rule_id))
    assign_occurrences(findings)

    for f in findings:
        if f.fingerprint in suppressed:
            f.suppressed = True

    return ScanResult(
        target=str(root),
        scanned_at=datetime.now(UTC).isoformat(timespec="seconds"),
        elapsed_sec=round(time.monotonic() - started, 2),
        osv_status=osv_status,
        total_files=total_files,
        findings=findings,
        components=components,
    )
