"""CVSS v3.x ベーススコアの簡易計算（ベクタ文字列から重要度ラベルを導出）。"""
from __future__ import annotations

import math
from typing import Optional

_W = {
    "AV": {"N": 0.85, "A": 0.62, "L": 0.55, "P": 0.2},
    "AC": {"L": 0.77, "H": 0.44},
    "PR_U": {"N": 0.85, "L": 0.62, "H": 0.27},   # Scope Unchanged
    "PR_C": {"N": 0.85, "L": 0.68, "H": 0.5},    # Scope Changed
    "UI": {"N": 0.85, "R": 0.62},
    "C": {"H": 0.56, "L": 0.22, "N": 0.0},
    "I": {"H": 0.56, "L": 0.22, "N": 0.0},
    "A": {"H": 0.56, "L": 0.22, "N": 0.0},
}


def base_score(vector: str) -> Optional[float]:
    try:
        parts = dict(p.split(":") for p in vector.replace("CVSS:3.1/", "").replace("CVSS:3.0/", "").split("/") if ":" in p)
        av = _W["AV"][parts["AV"]]
        ac = _W["AC"][parts["AC"]]
        ui = _W["UI"][parts["UI"]]
        scope_changed = parts["S"] == "C"
        pr = (_W["PR_C"] if scope_changed else _W["PR_U"])[parts["PR"]]
        c = _W["C"][parts["C"]]
        i = _W["I"][parts["I"]]
        a = _W["A"][parts["A"]]

        iss = 1 - (1 - c) * (1 - i) * (1 - a)
        if scope_changed:
            impact = 7.52 * (iss - 0.029) - 3.25 * ((iss - 0.02) ** 15)
        else:
            impact = 6.42 * iss
        exploit = 8.22 * av * ac * pr * ui
        if impact <= 0:
            return 0.0
        if scope_changed:
            score = min(1.08 * (impact + exploit), 10)
        else:
            score = min(impact + exploit, 10)
        return math.ceil(score * 10) / 10.0
    except Exception:
        return None


def score_to_severity(score: Optional[float]) -> Optional[str]:
    if score is None:
        return None
    if score >= 9.0:
        return "CRITICAL"
    if score >= 7.0:
        return "HIGH"
    if score >= 4.0:
        return "MEDIUM"
    if score > 0.0:
        return "LOW"
    return "INFO"


def severity_from_label(label: str) -> Optional[str]:
    if not label:
        return None
    l = label.strip().upper()
    if l in ("MODERATE",):
        return "MEDIUM"
    if l in ("CRITICAL", "HIGH", "MEDIUM", "LOW", "INFO"):
        return l
    return None
