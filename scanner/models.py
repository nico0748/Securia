"""共通データモデルとユーティリティ。"""
from __future__ import annotations

import hashlib
from dataclasses import dataclass, field, asdict
from typing import List, Optional

# 重要度の順位（大きいほど深刻）
SEVERITY_ORDER = {
    "CRITICAL": 4,
    "HIGH": 3,
    "MEDIUM": 2,
    "LOW": 1,
    "INFO": 0,
}


@dataclass
class Finding:
    """1件の検出結果（脆弱性/問題）。"""
    category: str            # dependency | static | config
    severity: str            # CRITICAL | HIGH | MEDIUM | LOW | INFO
    title: str
    description: str = ""
    recommendation: str = ""
    file: str = ""           # スキャン対象ルートからの相対パス
    line: int = 0
    package: str = ""        # 依存関係の場合のパッケージ名
    version: str = ""        # 依存関係の場合のバージョン
    ecosystem: str = ""      # npm / PyPI / Go など
    rule_id: str = ""
    references: List[str] = field(default_factory=list)
    fixed_version: str = ""
    _id: str = ""

    def finalize(self) -> "Finding":
        if not self._id:
            raw = f"{self.category}|{self.rule_id}|{self.file}|{self.line}|{self.package}|{self.title}"
            self._id = hashlib.sha1(raw.encode("utf-8")).hexdigest()[:12]
        self.severity = self.severity.upper()
        if self.severity not in SEVERITY_ORDER:
            self.severity = "INFO"
        return self

    def to_dict(self) -> dict:
        d = asdict(self)
        d["id"] = self._id
        d.pop("_id", None)
        return d


@dataclass
class Component:
    """SBOM上の1コンポーネント。"""
    name: str
    version: str
    ecosystem: str
    file: str = ""
    scope: str = "runtime"   # runtime | dev
    vuln_count: int = 0
    max_severity: str = "INFO"

    def to_dict(self) -> dict:
        return asdict(self)


def severity_rank(sev: str) -> int:
    return SEVERITY_ORDER.get((sev or "INFO").upper(), 0)


def worst_severity(sevs: List[str]) -> str:
    best = "INFO"
    for s in sevs:
        if severity_rank(s) > severity_rank(best):
            best = s.upper()
    return best
