"""CVSS v3.x ベーススコアの計算とラベル化。

OSV の脆弱性レコードはベンダごとに重要度の表現がまちまちなので、
CVSS ベクタが付いていればそこから自前で算出して揃える。
"""
from __future__ import annotations

import math

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

_PREFIXES = ("CVSS:3.1/", "CVSS:3.0/")


def base_score(vector: str) -> float | None:
    """CVSS v3 ベクタ文字列からベーススコアを求める。解釈できなければ None。"""
    if not vector:
        return None
    v = vector.strip()
    for prefix in _PREFIXES:
        if v.startswith(prefix):
            v = v[len(prefix):]
            break
    try:
        parts = dict(p.split(":", 1) for p in v.split("/") if ":" in p)
        av = _W["AV"][parts["AV"]]
        ac = _W["AC"][parts["AC"]]
        ui = _W["UI"][parts["UI"]]
        scope_changed = parts["S"] == "C"
        pr = (_W["PR_C"] if scope_changed else _W["PR_U"])[parts["PR"]]
        c = _W["C"][parts["C"]]
        i = _W["I"][parts["I"]]
        a = _W["A"][parts["A"]]
    except (KeyError, ValueError):
        return None

    iss = 1 - (1 - c) * (1 - i) * (1 - a)
    # 仕様書の2式をそのままの形で残す。三項演算子に潰すと元の定義と照合しづらい。
    if scope_changed:  # noqa: SIM108
        impact = 7.52 * (iss - 0.029) - 3.25 * ((iss - 0.02) ** 15)
    else:
        impact = 6.42 * iss
    if impact <= 0:
        return 0.0

    exploitability = 8.22 * av * ac * pr * ui
    raw = 1.08 * (impact + exploitability) if scope_changed else impact + exploitability
    return math.ceil(min(raw, 10.0) * 10) / 10.0


def score_to_severity(score: float | None) -> str | None:
    """CVSS スコアを重要度ラベルへ（CVSS v3 の定義に従う）。"""
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


def severity_from_label(label: str) -> str | None:
    """データベース側が持つ重要度ラベルを正規化する。"""
    if not label:
        return None
    normalized = label.strip().upper()
    if normalized == "MODERATE":     # GitHub Advisory 由来
        return "MEDIUM"
    if normalized in ("CRITICAL", "HIGH", "MEDIUM", "LOW", "INFO"):
        return normalized
    return None
