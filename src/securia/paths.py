"""データディレクトリの解決と、スキャン対象パスの検証。

スキャン対象パスの検証はセキュリティ境界の一部である。ローカルサーバは
ブラウザから任意のパスを受け取りうるため、許可ルート配下に限定し、
資格情報が置かれがちなディレクトリは明示的に拒否する。
"""
from __future__ import annotations

import os
from pathlib import Path

APP_NAME = "securia"

# 明示的に許可されない限りスキャンを拒否するディレクトリ名。
# ここに入るのは「中身がほぼ確実に秘密情報」であるもののみ。
DENY_BASENAMES = frozenset({
    ".ssh", ".gnupg", ".aws", ".azure", ".kube", ".docker",
    ".password-store", "keyrings", ".gem", ".netrc",
})

# ルートに近すぎてスキャンが暴走する（かつ意味がない）パス。
DENY_EXACT = frozenset({"/", "/etc", "/var", "/usr", "/bin", "/sbin", "/System", "/Library", "/private"})


class PathNotAllowed(Exception):
    """スキャン対象として許可されていないパス。"""


def data_dir() -> Path:
    """スキャン履歴 DB などを置くディレクトリ。

    SECURIA_DATA_DIR で上書きできる（テストと、可搬な運用のため）。
    それ以外は XDG_DATA_HOME、無ければ ~/.local/share を使う。
    """
    env = os.environ.get("SECURIA_DATA_DIR")
    if env:
        p = Path(env).expanduser()
    else:
        xdg = os.environ.get("XDG_DATA_HOME")
        base = Path(xdg).expanduser() if xdg else Path.home() / ".local" / "share"
        p = base / APP_NAME
    p.mkdir(parents=True, exist_ok=True)
    return p


def config_search_paths() -> list[Path]:
    """設定ファイルの探索順。先に見つかったものを使う。"""
    out = [Path.cwd() / "securia.toml"]
    xdg = os.environ.get("XDG_CONFIG_HOME")
    base = Path(xdg).expanduser() if xdg else Path.home() / ".config"
    out.append(base / APP_NAME / "config.toml")
    return out


def normalize(path: str | os.PathLike[str]) -> Path:
    """~ 展開と絶対パス化。シンボリックリンクも解決する。

    resolve() まで行うのは、許可ルートの判定をリンク経由で迂回されないため。
    """
    return Path(os.path.expandvars(str(path))).expanduser().resolve()


def ensure_scannable(target: str | os.PathLike[str], allowed_roots: list[str]) -> Path:
    """スキャン対象として妥当なら解決済み Path を返し、駄目なら PathNotAllowed。

    allowed_roots が空リストなら「制限なし」として扱う。ただし DENY_* は常に効く。
    """
    p = normalize(target)

    if not p.exists():
        raise PathNotAllowed(f"ディレクトリが見つかりません: {p}")
    if not p.is_dir():
        raise PathNotAllowed(f"ディレクトリではありません: {p}")

    if str(p) in DENY_EXACT:
        raise PathNotAllowed(f"システムディレクトリはスキャンできません: {p}")
    if p.name in DENY_BASENAMES:
        raise PathNotAllowed(f"資格情報が置かれるディレクトリはスキャンできません: {p}")

    if allowed_roots:
        roots = [normalize(r) for r in allowed_roots]
        if not any(_is_within(p, r) for r in roots):
            listed = ", ".join(str(r) for r in roots)
            raise PathNotAllowed(
                f"許可されたルートの外です: {p}\n"
                f"許可ルート: {listed}\n"
                f"securia.toml の [scan] allowed_roots に追加してください。"
            )
    return p


def _is_within(path: Path, root: Path) -> bool:
    try:
        path.relative_to(root)
        return True
    except ValueError:
        return False
