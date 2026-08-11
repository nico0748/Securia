"""共通データモデル。

Finding の同一性は fingerprint で表す。行番号を含めないのが要点で、
コードの前後に行が挿入されただけの検出を「新規」と誤判定させないため。
代わりに一致した行の内容ハッシュを使うので、中身が変われば別物になる。
"""
from __future__ import annotations

import hashlib
import re
from dataclasses import asdict, dataclass, field

# 重要度の順位（大きいほど深刻）
SEVERITY_ORDER: dict[str, int] = {
    "CRITICAL": 4,
    "HIGH": 3,
    "MEDIUM": 2,
    "LOW": 1,
    "INFO": 0,
}

SEVERITIES: tuple[str, ...] = ("CRITICAL", "HIGH", "MEDIUM", "LOW", "INFO")
CATEGORIES: tuple[str, ...] = ("dependency", "static", "config")

_WS = re.compile(r"\s+")


def severity_rank(sev: str) -> int:
    return SEVERITY_ORDER.get((sev or "INFO").upper(), 0)


def worst_severity(sevs: list[str]) -> str:
    """与えられた重要度のうち最も深刻なものを返す。"""
    best = "INFO"
    for s in sevs:
        if severity_rank(s) > severity_rank(best):
            best = s.upper()
    return best


def normalize_severity(sev: str) -> str:
    s = (sev or "").upper()
    return s if s in SEVERITY_ORDER else "INFO"


def _hash(*parts: str) -> str:
    h = hashlib.sha256("\x1f".join(parts).encode("utf-8", "replace"))
    return h.hexdigest()[:16]


@dataclass
class Finding:
    """1件の検出結果。"""

    category: str            # dependency | static | config
    severity: str            # CRITICAL | HIGH | MEDIUM | LOW | INFO
    title: str
    rule_id: str
    description: str = ""
    recommendation: str = ""
    file: str = ""           # スキャン対象ルートからの相対パス
    line: int = 0
    package: str = ""
    version: str = ""
    ecosystem: str = ""
    references: list[str] = field(default_factory=list)
    fixed_version: str = ""

    # 一致した行の生テキスト。fingerprint の材料に使うだけで、
    # 秘密情報を含みうるため DB にも API レスポンスにも出さない。
    evidence: str = ""

    fingerprint: str = ""
    occurrence: int = 0      # 同一 fingerprint がスキャン内で複数出たときの連番
    suppressed: bool = False
    status: str = "existing"  # new | existing（前回スキャンとの比較結果）

    def compute_fingerprint(self) -> str:
        """行番号に依存しない安定 ID を計算して自身に設定する。"""
        self.severity = normalize_severity(self.severity)
        evidence_key = _WS.sub(" ", self.evidence).strip()
        self.fingerprint = _hash(
            self.category,
            self.rule_id,
            self.file,
            self.package,
            self.version if self.category == "dependency" else "",
            evidence_key,
        )
        return self.fingerprint

    @property
    def uid(self) -> str:
        """スキャン内で一意なキー。同一 fingerprint の重複を連番で区別する。"""
        return f"{self.fingerprint}:{self.occurrence}"

    def to_dict(self) -> dict:
        d = asdict(self)
        d.pop("evidence", None)   # 秘密情報を外に出さない
        d["uid"] = self.uid
        return d


@dataclass
class Component:
    """SBOM 上の1コンポーネント。"""

    name: str
    version: str
    ecosystem: str
    file: str = ""
    scope: str = "runtime"   # runtime | dev
    vuln_count: int = 0
    max_severity: str = "INFO"

    @property
    def key(self) -> tuple[str, str, str]:
        return (self.ecosystem, self.name, self.version)

    def to_dict(self) -> dict:
        return asdict(self)


def assign_occurrences(findings: list[Finding]) -> None:
    """同一 fingerprint の検出に、出現順で連番を振る。

    ソート済みの安定した順序で呼ぶこと。順序が変わると連番も変わり、
    差分判定が揺れる。
    """
    seen: dict[str, int] = {}
    for f in findings:
        n = seen.get(f.fingerprint, 0)
        f.occurrence = n
        seen[f.fingerprint] = n + 1
