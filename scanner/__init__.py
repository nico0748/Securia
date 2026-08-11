"""スキャナ・オーケストレータ。3種のスキャンを実行して結果を集約する。"""
from __future__ import annotations

import os
import time
from typing import Dict

from . import dependency, static_code, config_scan
from .models import SEVERITY_ORDER, severity_rank

SEVERITIES = ["CRITICAL", "HIGH", "MEDIUM", "LOW", "INFO"]


def run_scan(root: str) -> Dict:
    root = os.path.abspath(os.path.expanduser(root))
    if not os.path.isdir(root):
        raise NotADirectoryError(f"ディレクトリが見つかりません: {root}")

    t0 = time.time()

    dep_findings, components, osv_online = dependency.scan(root)
    static_findings = static_code.scan(root)
    config_findings = config_scan.scan(root)

    all_findings = dep_findings + static_findings + config_findings
    # 重要度順→カテゴリ→ファイルでソート
    all_findings.sort(key=lambda f: (-severity_rank(f.severity), f.category, f.file, f.line))

    # サマリー集計
    severity_counts = {s: 0 for s in SEVERITIES}
    category_counts = {"dependency": 0, "static": 0, "config": 0}
    for f in all_findings:
        severity_counts[f.severity] = severity_counts.get(f.severity, 0) + 1
        category_counts[f.category] = category_counts.get(f.category, 0) + 1

    # ファイル数など
    total_files = 0
    for dp, dn, fn in os.walk(root):
        from .util import SKIP_DIRS
        dn[:] = [d for d in dn if d not in SKIP_DIRS]
        total_files += len(fn)

    ecosystems: Dict[str, int] = {}
    for c in components:
        ecosystems[c.ecosystem] = ecosystems.get(c.ecosystem, 0) + 1

    vuln_components = sum(1 for c in components if c.vuln_count > 0)

    elapsed = round(time.time() - t0, 2)

    return {
        "target": root,
        "scanned_at": time.strftime("%Y-%m-%d %H:%M:%S"),
        "elapsed_sec": elapsed,
        "osv_online": osv_online,
        "summary": {
            "total_findings": len(all_findings),
            "severity_counts": severity_counts,
            "category_counts": category_counts,
            "total_files": total_files,
            "total_components": len(components),
            "vulnerable_components": vuln_components,
            "ecosystems": ecosystems,
        },
        "findings": [f.to_dict() for f in all_findings],
        "components": [c.to_dict() for c in sorted(
            components, key=lambda c: (-severity_rank(c.max_severity), -c.vuln_count, c.name))],
    }
