"""スキャン対象パスの検証。サーバのセキュリティ境界の一部。"""
from __future__ import annotations

from pathlib import Path

import pytest

from securia.paths import PathNotAllowed, data_dir, ensure_scannable, normalize


def test_accepts_directory_within_allowed_root(tmp_path: Path) -> None:
    project = tmp_path / "project"
    project.mkdir()
    assert ensure_scannable(str(project), [str(tmp_path)]) == project.resolve()


def test_rejects_outside_allowed_roots(tmp_path: Path) -> None:
    other = tmp_path / "other"
    allowed = tmp_path / "allowed"
    other.mkdir()
    allowed.mkdir()
    with pytest.raises(PathNotAllowed, match="許可されたルートの外"):
        ensure_scannable(str(other), [str(allowed)])


def test_empty_allowed_roots_means_unrestricted(tmp_path: Path) -> None:
    assert ensure_scannable(str(tmp_path), []) == tmp_path.resolve()


def test_rejects_missing_path(tmp_path: Path) -> None:
    with pytest.raises(PathNotAllowed, match="見つかりません"):
        ensure_scannable(str(tmp_path / "nope"), [])


def test_rejects_file(tmp_path: Path) -> None:
    f = tmp_path / "a.txt"
    f.write_text("x")
    with pytest.raises(PathNotAllowed, match="ディレクトリではありません"):
        ensure_scannable(str(f), [])


@pytest.mark.parametrize("name", [".ssh", ".aws", ".gnupg", ".kube"])
def test_rejects_credential_directories(tmp_path: Path, name: str) -> None:
    """許可ルートの中にあっても資格情報ディレクトリは拒否する。"""
    d = tmp_path / name
    d.mkdir()
    with pytest.raises(PathNotAllowed, match="資格情報"):
        ensure_scannable(str(d), [str(tmp_path)])


def test_rejects_system_root() -> None:
    with pytest.raises(PathNotAllowed, match="システムディレクトリ"):
        ensure_scannable("/", [])


def test_symlink_cannot_escape_allowed_root(tmp_path: Path) -> None:
    """リンクを辿った先で判定するので、リンク経由の迂回はできない。"""
    outside = tmp_path / "outside"
    outside.mkdir()
    allowed = tmp_path / "allowed"
    allowed.mkdir()
    link = allowed / "escape"
    link.symlink_to(outside, target_is_directory=True)

    with pytest.raises(PathNotAllowed):
        ensure_scannable(str(link), [str(allowed)])


def test_normalize_expands_user_and_resolves(tmp_path: Path) -> None:
    nested = tmp_path / "a" / ".." / "b"
    (tmp_path / "b").mkdir(parents=True)
    (tmp_path / "a").mkdir(parents=True)
    assert normalize(str(nested)) == (tmp_path / "b").resolve()
    assert normalize("~").is_absolute()


def test_data_dir_honours_env(tmp_path, monkeypatch) -> None:
    monkeypatch.setenv("SECURIA_DATA_DIR", str(tmp_path / "custom"))
    assert data_dir() == tmp_path / "custom"
    assert data_dir().is_dir()
