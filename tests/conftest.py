"""共通フィクスチャ。"""
from __future__ import annotations

from pathlib import Path

import pytest

from securia.config import Config, ScanConfig
from securia.scan.walker import FileEntry
from securia.store import Store


@pytest.fixture
def cfg(tmp_path: Path) -> Config:
    """一時ディレクトリだけをスキャン対象として許可する設定。"""
    c = Config()
    c.scan = ScanConfig(allowed_roots=[str(tmp_path)])
    c.osv.enabled = False
    return c


@pytest.fixture
def store(tmp_path: Path) -> Store:
    s = Store(tmp_path / "test.db")
    yield s
    s.close()


def make_entry(tmp_path: Path, relpath: str, content: str = "") -> FileEntry:
    """相対パスからファイルを作り、対応する FileEntry を返す。"""
    full = tmp_path / relpath
    full.parent.mkdir(parents=True, exist_ok=True)
    full.write_text(content, encoding="utf-8")
    name = full.name
    lname = name.lower()
    return FileEntry(
        path=full,
        relpath=relpath,
        name=name,
        lname=lname,
        ext=("." + lname.rsplit(".", 1)[1]) if "." in lname else "",
        size=full.stat().st_size,
    )


@pytest.fixture
def entry_factory(tmp_path: Path):
    def factory(relpath: str, content: str = "") -> FileEntry:
        return make_entry(tmp_path, relpath, content)
    return factory
