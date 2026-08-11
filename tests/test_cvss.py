"""CVSS v3 ベーススコア計算。"""
from __future__ import annotations

import pytest

from securia.scan import cvss


@pytest.mark.parametrize(
    ("vector", "expected"),
    [
        # 公式の代表的なベクタと期待スコア
        ("CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:H", 9.8),
        ("CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:C/C:H/I:H/A:H", 10.0),
        ("CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:N/I:N/A:H", 7.5),
        ("CVSS:3.1/AV:L/AC:L/PR:L/UI:N/S:U/C:H/I:N/A:N", 5.5),
        ("CVSS:3.0/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:H", 9.8),
        # プレフィクス無しでも読める
        ("AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:H", 9.8),
    ],
)
def test_base_score(vector: str, expected: float) -> None:
    assert cvss.base_score(vector) == pytest.approx(expected)


def test_no_impact_scores_zero() -> None:
    assert cvss.base_score("CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:N/I:N/A:N") == 0.0


@pytest.mark.parametrize("vector", ["", "garbage", "CVSS:3.1/AV:X/AC:L", "CVSS:3.1/AV:N"])
def test_unparsable_vectors_return_none(vector: str) -> None:
    assert cvss.base_score(vector) is None


@pytest.mark.parametrize(
    ("score", "label"),
    [(10.0, "CRITICAL"), (9.0, "CRITICAL"), (8.9, "HIGH"), (7.0, "HIGH"),
     (6.9, "MEDIUM"), (4.0, "MEDIUM"), (3.9, "LOW"), (0.1, "LOW"), (0.0, "INFO")],
)
def test_score_to_severity(score: float, label: str) -> None:
    assert cvss.score_to_severity(score) == label


def test_score_to_severity_none() -> None:
    assert cvss.score_to_severity(None) is None


@pytest.mark.parametrize(
    ("label", "expected"),
    [("moderate", "MEDIUM"), ("MODERATE", "MEDIUM"), ("high", "HIGH"),
     (" Critical ", "CRITICAL"), ("", None), ("bogus", None)],
)
def test_severity_from_label(label: str, expected: str | None) -> None:
    assert cvss.severity_from_label(label) == expected
