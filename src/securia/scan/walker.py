"""ディレクトリ走査とファイル読み込み。

以前は依存・静的・設定の各スキャナがそれぞれ os.walk していたため、
同じツリーを4周し同じファイルを何度も読んでいた。ここで1周に統合し、
読んだ内容を各スキャナへ配る。
"""
from __future__ import annotations

import os
from collections.abc import Iterator
from dataclasses import dataclass
from fnmatch import fnmatch
from pathlib import Path
from threading import Event

from ..config import ScanConfig

# 静的解析でスキップする拡張子（バイナリ・巨大生成物）
BINARY_EXT = frozenset({
    ".png", ".jpg", ".jpeg", ".gif", ".bmp", ".ico", ".svg", ".webp",
    ".pdf", ".zip", ".gz", ".tar", ".rar", ".7z", ".jar", ".war", ".class",
    ".woff", ".woff2", ".ttf", ".eot", ".mp3", ".mp4", ".mov", ".avi",
    ".so", ".dll", ".dylib", ".exe", ".bin", ".o", ".a", ".pyc", ".wasm",
})

# 依存関係スキャナが個別に解釈するファイル。静的解析の対象からは外す。
MANIFEST_NAMES = frozenset({
    "package.json", "package-lock.json", "yarn.lock", "pnpm-lock.yaml",
    "requirements.txt", "requirements-dev.txt", "pipfile.lock",
    "poetry.lock", "go.mod", "go.sum", "cargo.lock", "gemfile.lock",
    "composer.lock",
})


class ScanCancelled(Exception):
    """利用者がスキャンを中断した。"""


@dataclass(frozen=True)
class FileEntry:
    path: Path
    relpath: str      # スキャンルートからの相対パス（区切りは / に正規化）
    name: str         # ベース名（元の大小文字）
    lname: str        # ベース名（小文字）
    ext: str          # 拡張子（小文字、ドット込み）
    size: int

    @property
    def is_manifest(self) -> bool:
        return self.lname in MANIFEST_NAMES

    @property
    def is_binary_ext(self) -> bool:
        return self.ext in BINARY_EXT


def walk(root: Path, cfg: ScanConfig, cancel: Event | None = None) -> Iterator[FileEntry]:
    """スキャン対象ファイルを1度だけ列挙する。

    cancel がセットされたら ScanCancelled を送出して即座に打ち切る。
    """
    root = Path(root)
    skip_dirs = cfg.skip_dirs
    globs = cfg.skip_globs

    for dirpath, dirnames, filenames in os.walk(root, followlinks=cfg.follow_symlinks):
        if cancel is not None and cancel.is_set():
            raise ScanCancelled

        # 走査前に枝を刈る。dirnames の in-place 変更が os.walk への指示になる。
        dirnames[:] = [
            d for d in dirnames
            if d not in skip_dirs and not d.startswith(".terraform")
        ]

        for fn in filenames:
            full = Path(dirpath) / fn
            relpath = _rel(root, full)
            if globs and any(fnmatch(relpath, g) for g in globs):
                continue
            try:
                size = full.stat().st_size
            except OSError:
                continue  # 読めない/消えた/壊れたリンク
            if not cfg.follow_symlinks and full.is_symlink():
                continue

            lname = fn.lower()
            yield FileEntry(
                path=full,
                relpath=relpath,
                name=fn,
                lname=lname,
                ext=os.path.splitext(lname)[1],
                size=size,
            )


def _rel(root: Path, path: Path) -> str:
    try:
        return str(path.relative_to(root)).replace(os.sep, "/")
    except ValueError:
        return str(path).replace(os.sep, "/")


def read_text(entry: FileEntry, max_bytes: int) -> str:
    """テキストとして読む。バイナリ・巨大ファイル・読めないものは空文字。"""
    if entry.size > max_bytes:
        return ""
    for enc in ("utf-8", "latin-1"):
        try:
            with open(entry.path, encoding=enc, errors="strict") as f:
                return f.read()
        except (UnicodeDecodeError, OSError):
            continue
    try:
        with open(entry.path, encoding="utf-8", errors="ignore") as f:
            return f.read()
    except OSError:
        return ""


def read_snippet(path: Path, line: int, context: int = 3) -> list[dict]:
    """UI の詳細表示用に、指定行の周辺をディスクから直接読む。

    秘密情報を DB に持たないため、必要になった時点でその場で読む。
    戻り値は [{"line": 12, "text": "...", "target": true}, ...]。
    """
    if line <= 0:
        return []
    try:
        with open(path, encoding="utf-8", errors="replace") as f:
            lines = f.readlines()
    except OSError:
        return []

    start = max(1, line - context)
    end = min(len(lines), line + context)
    return [
        {"line": i, "text": lines[i - 1].rstrip("\n")[:400], "target": i == line}
        for i in range(start, end + 1)
    ]
