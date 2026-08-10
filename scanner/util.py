"""ファイル探索の共通ユーティリティ。"""
from __future__ import annotations

import os
from typing import Iterator, Tuple

# 走査時にまるごとスキップするディレクトリ
SKIP_DIRS = {
    ".git", ".hg", ".svn", "node_modules", "bower_components", "vendor",
    "dist", "build", "out", ".next", ".nuxt", "target", ".venv", "venv",
    "env", "__pycache__", ".mypy_cache", ".pytest_cache", ".gradle",
    ".idea", ".vscode", "coverage", ".terraform", ".cache", "site-packages",
}

# 静的解析でスキップする拡張子（バイナリ・巨大生成物）
BINARY_EXT = {
    ".png", ".jpg", ".jpeg", ".gif", ".bmp", ".ico", ".svg", ".webp",
    ".pdf", ".zip", ".gz", ".tar", ".rar", ".7z", ".jar", ".war", ".class",
    ".woff", ".woff2", ".ttf", ".eot", ".mp3", ".mp4", ".mov", ".avi",
    ".so", ".dll", ".dylib", ".exe", ".bin", ".o", ".a", ".pyc", ".wasm",
    ".lock",  # ロックファイルは依存スキャナが個別処理
}

MAX_FILE_BYTES = 2 * 1024 * 1024  # 2MB を超えるファイルは静的解析対象外


def walk_files(root: str) -> Iterator[str]:
    """SKIP_DIRS を除外しつつ全ファイルの絶対パスを返す。"""
    for dirpath, dirnames, filenames in os.walk(root):
        dirnames[:] = [d for d in dirnames if d not in SKIP_DIRS and not d.startswith(".terraform")]
        for fn in filenames:
            yield os.path.join(dirpath, fn)


def rel(root: str, path: str) -> str:
    try:
        return os.path.relpath(path, root)
    except ValueError:
        return path


def read_text(path: str) -> str:
    try:
        if os.path.getsize(path) > MAX_FILE_BYTES:
            return ""
    except OSError:
        return ""
    for enc in ("utf-8", "latin-1"):
        try:
            with open(path, "r", encoding=enc, errors="strict") as f:
                return f.read()
        except (UnicodeDecodeError, OSError):
            continue
    try:
        with open(path, "r", encoding="utf-8", errors="ignore") as f:
            return f.read()
    except OSError:
        return ""


def read_lines(path: str) -> list:
    text = read_text(path)
    return text.splitlines() if text else []
