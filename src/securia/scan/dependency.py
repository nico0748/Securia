"""依存関係マニフェスト/ロックファイルの解析（SBOM 構築）。

OSV への問い合わせはここではやらない（securia.osv が担当）。
このモジュールは純粋にテキスト → Component の変換に徹するので、
ネットワーク無しでテストできる。

ロックファイルとマニフェストが同じディレクトリにある場合は、
実際に入るバージョンが確定しているロックファイル側を採用する。
"""
from __future__ import annotations

import json
import posixpath
import re
from dataclasses import dataclass, field

from ..models import Component
from .walker import FileEntry

# ロックファイル優先の判定に使う種別
KIND_NPM_LOCK = "npm-lock"
KIND_NPM_MANIFEST = "npm-manifest"
KIND_PY_LOCK = "py-lock"
KIND_PY_MANIFEST = "py-manifest"
KIND_GO = "go"


@dataclass
class ManifestResult:
    dirpath: str
    kind: str
    components: list[Component] = field(default_factory=list)


def _clean_version(v: str) -> str:
    """`^1.2.3` `>=2.0` のようなレンジ表記から代表バージョンを取り出す。"""
    if not v:
        return ""
    v = v.strip().strip("\"'")
    v = re.sub(r"^[\^~>=<\s]+", "", v)
    m = re.match(r"(\d+\.\d+(?:\.\d+)?(?:[-.][0-9A-Za-z.]+)?)", v)
    return m.group(1) if m else ""


# ------------------------- 各形式のパーサ -------------------------
def parse_package_json(text: str, relpath: str) -> list[Component]:
    try:
        data = json.loads(text)
    except (ValueError, TypeError):
        return []
    if not isinstance(data, dict):
        return []
    out: list[Component] = []
    for scope, key in (("runtime", "dependencies"), ("dev", "devDependencies")):
        section = data.get(key)
        if not isinstance(section, dict):
            continue
        for name, ver in section.items():
            cv = _clean_version(str(ver))
            if cv:
                out.append(Component(name=name, version=cv, ecosystem="npm", file=relpath, scope=scope))
    return out


def parse_package_lock(text: str, relpath: str) -> list[Component]:
    try:
        data = json.loads(text)
    except (ValueError, TypeError):
        return []
    if not isinstance(data, dict):
        return []

    out: list[Component] = []
    seen: set[tuple[str, str]] = set()

    def push(name: str, version: str, scope: str) -> None:
        if not name or not version:
            return
        key = (name, version)
        if key in seen:
            return
        seen.add(key)
        out.append(Component(name=name, version=version, ecosystem="npm", file=relpath, scope=scope))

    packages = data.get("packages")
    if isinstance(packages, dict):          # lockfile v2/v3
        for pkgpath, meta in packages.items():
            if not pkgpath or not isinstance(meta, dict) or "version" not in meta:
                continue
            name = pkgpath.split("node_modules/")[-1]
            push(name, str(meta["version"]), "dev" if meta.get("dev") else "runtime")
        return out

    deps = data.get("dependencies")
    if isinstance(deps, dict):              # lockfile v1
        def walk(node: dict, scope: str) -> None:
            for name, meta in node.items():
                if not isinstance(meta, dict):
                    continue
                ver = _clean_version(str(meta.get("version", "")))
                push(name, ver, "dev" if meta.get("dev") else scope)
                nested = meta.get("dependencies")
                if isinstance(nested, dict):
                    walk(nested, scope)
        walk(deps, "runtime")
    return out


def parse_yarn_lock(text: str, relpath: str) -> list[Component]:
    out: list[Component] = []
    for block in re.split(r"\n(?=\S)", text):
        header = block.split("\n", 1)[0]
        m = re.match(r'"?(@?[^@\s,"]+)@', header)
        vm = re.search(r'\n\s+version:?\s+"?([0-9][^"\s]*)"?', block)
        if m and vm:
            out.append(Component(name=m.group(1), version=vm.group(1), ecosystem="npm",
                                 file=relpath, scope="runtime"))
    return out


def parse_requirements(text: str, relpath: str) -> list[Component]:
    out: list[Component] = []
    for line in text.splitlines():
        line = line.strip()
        if not line or line.startswith(("#", "-")):
            continue
        m = re.match(r"([A-Za-z0-9_.\-]+)\s*==\s*([0-9][^\s;#]*)", line)
        if m:
            out.append(Component(name=m.group(1).lower(), version=m.group(2), ecosystem="PyPI",
                                 file=relpath, scope="runtime"))
    return out


def parse_poetry_lock(text: str, relpath: str) -> list[Component]:
    out: list[Component] = []
    for block in text.split("[[package]]")[1:]:
        nm = re.search(r'name\s*=\s*"([^"]+)"', block)
        vm = re.search(r'version\s*=\s*"([^"]+)"', block)
        if nm and vm:
            # category = "dev" は Poetry 1.2 未満の表現
            scope = "dev" if re.search(r'category\s*=\s*"dev"', block) else "runtime"
            out.append(Component(name=nm.group(1).lower(), version=vm.group(1), ecosystem="PyPI",
                                 file=relpath, scope=scope))
    return out


def parse_pipfile_lock(text: str, relpath: str) -> list[Component]:
    try:
        data = json.loads(text)
    except (ValueError, TypeError):
        return []
    if not isinstance(data, dict):
        return []
    out: list[Component] = []
    for scope, key in (("runtime", "default"), ("dev", "develop")):
        section = data.get(key)
        if not isinstance(section, dict):
            continue
        for name, meta in section.items():
            if not isinstance(meta, dict):
                continue
            ver = _clean_version(str(meta.get("version", "")))
            if ver:
                out.append(Component(name=name.lower(), version=ver, ecosystem="PyPI",
                                     file=relpath, scope=scope))
    return out


def parse_go_mod(text: str, relpath: str) -> list[Component]:
    out: list[Component] = []
    in_block = False
    for line in text.splitlines():
        s = line.strip()
        if s.startswith("require ("):
            in_block = True
            continue
        if in_block and s == ")":
            in_block = False
            continue
        if s.startswith("//") or not s:
            continue
        m = re.match(r"(?:require\s+)?([\w./\-]+)\s+v([0-9][^\s/]*)", s)
        if m and "." in m.group(1):
            out.append(Component(name=m.group(1), version="v" + m.group(2), ecosystem="Go",
                                 file=relpath, scope="runtime"))
    return out


_PARSERS: dict[str, tuple[str, object]] = {
    "package-lock.json": (KIND_NPM_LOCK, parse_package_lock),
    "yarn.lock": (KIND_NPM_LOCK, parse_yarn_lock),
    "package.json": (KIND_NPM_MANIFEST, parse_package_json),
    "poetry.lock": (KIND_PY_LOCK, parse_poetry_lock),
    "pipfile.lock": (KIND_PY_LOCK, parse_pipfile_lock),
    "requirements.txt": (KIND_PY_MANIFEST, parse_requirements),
    "requirements-dev.txt": (KIND_PY_MANIFEST, parse_requirements),
    "go.mod": (KIND_GO, parse_go_mod),
}


def applies_to(entry: FileEntry) -> bool:
    return entry.lname in _PARSERS


def collect_from_file(entry: FileEntry, text: str) -> ManifestResult | None:
    """1つのマニフェスト/ロックファイルを解析する。"""
    spec = _PARSERS.get(entry.lname)
    if spec is None or not text:
        return None
    kind, parser = spec
    components = parser(text, entry.relpath)  # type: ignore[operator]
    return ManifestResult(dirpath=posixpath.dirname(entry.relpath), kind=kind, components=components)


def resolve(results: list[ManifestResult]) -> list[Component]:
    """ロックファイル優先の解決と重複排除。

    同じディレクトリに package.json と package-lock.json があれば
    ロック側だけを採る。バージョンが確定しているのはロック側だから。
    """
    npm_lock_dirs = {r.dirpath for r in results if r.kind == KIND_NPM_LOCK}
    py_lock_dirs = {r.dirpath for r in results if r.kind == KIND_PY_LOCK}

    uniq: dict[tuple[str, str, str], Component] = {}
    for r in results:
        if r.kind == KIND_NPM_MANIFEST and r.dirpath in npm_lock_dirs:
            continue
        if r.kind == KIND_PY_MANIFEST and r.dirpath in py_lock_dirs:
            continue
        for c in r.components:
            uniq.setdefault(c.key, c)
    return list(uniq.values())
