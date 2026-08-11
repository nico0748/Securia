"""スキャンのオーケストレーション（走査 → 各スキャナ → 集計）。"""
from __future__ import annotations

import json
import threading
from pathlib import Path

import pytest

from securia.config import Config
from securia.engine import run_scan
from securia.scan.walker import ScanCancelled, read_snippet, walk


@pytest.fixture
def project(tmp_path: Path) -> Path:
    """一通りの問題を含むサンプルツリー。"""
    root = tmp_path / "project"
    (root / "src").mkdir(parents=True)
    (root / ".github" / "workflows").mkdir(parents=True)
    (root / "node_modules" / "junk").mkdir(parents=True)

    (root / "src" / "app.py").write_text(
        'AWS_KEY = "AKIAIOSFODNN7EXAMPLE"\nimport os\nos.system(cmd)\n', encoding="utf-8")
    (root / "package.json").write_text(
        json.dumps({"dependencies": {"lodash": "^4.17.20"}}), encoding="utf-8")
    (root / "requirements.txt").write_text("flask==2.0.1\n", encoding="utf-8")
    (root / "Dockerfile").write_text("FROM python:latest\n", encoding="utf-8")
    (root / ".github" / "workflows" / "ci.yml").write_text("on: pull_request_target\n", encoding="utf-8")
    # 除外されるべきもの
    (root / "node_modules" / "junk" / "evil.py").write_text("os.system(x)\n", encoding="utf-8")
    return root


def test_end_to_end(project: Path, cfg: Config) -> None:
    result = run_scan(project, cfg)
    rules = {f.rule_id for f in result.findings}

    assert "secret.aws_access_key" in rules
    assert "code.os_system" in rules
    assert "docker.latest_tag" in rules
    assert "gha.pr_target" in rules

    names = {c.name for c in result.components}
    assert names == {"lodash", "flask"}

    summary = result.summary()
    assert summary["total_findings"] == len(result.findings)
    assert summary["severity_counts"]["CRITICAL"] >= 1
    assert summary["ecosystems"] == {"npm": 1, "PyPI": 1}
    assert result.osv_status == "disabled"   # osv_client を渡していない


def test_skip_dirs_are_excluded(project: Path, cfg: Config) -> None:
    result = run_scan(project, cfg)
    assert all("node_modules" not in f.file for f in result.findings)


def test_file_count_matches_walk(project: Path, cfg: Config) -> None:
    """ファイル数は走査中に数える。別途ツリーを歩き直さない。"""
    expected = sum(1 for _ in walk(project, cfg.scan))
    assert run_scan(project, cfg).total_files == expected


def test_findings_sorted_by_severity(project: Path, cfg: Config) -> None:
    from securia.models import severity_rank
    ranks = [severity_rank(f.severity) for f in run_scan(project, cfg).findings]
    assert ranks == sorted(ranks, reverse=True)


def test_occurrences_are_assigned(project: Path, cfg: Config) -> None:
    result = run_scan(project, cfg)
    uids = [f.uid for f in result.findings]
    assert len(uids) == len(set(uids))


def test_suppressed_findings_excluded_from_summary(project: Path, cfg: Config) -> None:
    first = run_scan(project, cfg)
    target = first.findings[0].fingerprint

    second = run_scan(project, cfg, suppressed={target})
    assert second.summary()["suppressed_findings"] >= 1
    assert second.summary()["total_findings"] < first.summary()["total_findings"]
    assert len(second.findings) == len(first.findings)   # 消さずに印を付けるだけ


def test_progress_is_reported(project: Path, cfg: Config) -> None:
    events: list[tuple[str, int, int]] = []
    run_scan(project, cfg, progress=lambda p, c, t: events.append((p, c, t)))
    assert events
    assert events[0][0] == "ファイルを走査中"


def test_cancellation_stops_the_scan(project: Path, cfg: Config) -> None:
    cancel = threading.Event()
    cancel.set()
    with pytest.raises(ScanCancelled):
        run_scan(project, cfg, cancel=cancel)


def test_rule_config_is_applied(project: Path, cfg: Config) -> None:
    cfg.rules.disabled = ["secret.*"]
    rules = {f.rule_id for f in run_scan(project, cfg).findings}
    assert "secret.aws_access_key" not in rules
    assert "code.os_system" in rules


def test_skip_globs(project: Path, cfg: Config) -> None:
    cfg.scan.skip_globs = ["src/*.py"]
    assert all(not f.file.startswith("src/") for f in run_scan(project, cfg).findings)


def test_to_dict_omits_evidence(project: Path, cfg: Config) -> None:
    payload = run_scan(project, cfg).to_dict()
    assert "AKIAIOSFODNN7EXAMPLE" not in json.dumps(payload)
    assert all("evidence" not in f for f in payload["findings"])


def test_empty_directory(tmp_path: Path, cfg: Config) -> None:
    empty = tmp_path / "empty"
    empty.mkdir()
    result = run_scan(empty, cfg)
    assert result.findings == []
    assert result.total_files == 0
    assert result.summary()["total_findings"] == 0


def test_unreadable_and_binary_files_are_tolerated(tmp_path: Path, cfg: Config) -> None:
    root = tmp_path / "mixed"
    root.mkdir()
    (root / "image.png").write_bytes(b"\x89PNG\r\n\x1a\n\x00\x01\x02")
    (root / "big.py").write_text("x" * 5000, encoding="utf-8")
    cfg.scan.max_file_bytes = 100
    result = run_scan(root, cfg)          # 例外を出さずに終わること
    assert result.total_files == 2


# ---------------- コード抜粋 ----------------
def test_read_snippet_marks_target_line(tmp_path: Path) -> None:
    f = tmp_path / "a.py"
    f.write_text("\n".join(f"line{i}" for i in range(1, 11)), encoding="utf-8")

    lines = read_snippet(f, 5, context=2)
    assert [line["line"] for line in lines] == [3, 4, 5, 6, 7]
    assert [line["target"] for line in lines] == [False, False, True, False, False]
    assert lines[2]["text"] == "line5"


def test_read_snippet_clamps_at_file_edges(tmp_path: Path) -> None:
    f = tmp_path / "a.py"
    f.write_text("one\ntwo\n", encoding="utf-8")
    assert [line["line"] for line in read_snippet(f, 1, context=5)] == [1, 2]


def test_read_snippet_handles_missing_file_and_zero_line(tmp_path: Path) -> None:
    assert read_snippet(tmp_path / "nope.py", 1) == []
    assert read_snippet(tmp_path, 0) == []
