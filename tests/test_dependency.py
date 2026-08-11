"""依存関係マニフェストのパーサとロックファイル優先の解決。"""
from __future__ import annotations

import json

import pytest

from securia.scan import dependency as dep


def _names(components) -> set[str]:
    return {c.name for c in components}


def _by_name(components) -> dict:
    return {c.name: c for c in components}


# ---------------- package.json ----------------
def test_package_json_separates_scopes() -> None:
    text = json.dumps({
        "dependencies": {"lodash": "^4.17.20", "react": "18.2.0"},
        "devDependencies": {"jest": "~29.0.0"},
    })
    comps = _by_name(dep.parse_package_json(text, "package.json"))

    assert comps["lodash"].version == "4.17.20"     # レンジ記号を落とす
    assert comps["lodash"].scope == "runtime"
    assert comps["jest"].version == "29.0.0"
    assert comps["jest"].scope == "dev"
    assert all(c.ecosystem == "npm" for c in comps.values())


@pytest.mark.parametrize("text", ["", "{", "null", "[]", '"string"'])
def test_package_json_tolerates_broken_input(text: str) -> None:
    assert dep.parse_package_json(text, "package.json") == []


def test_package_json_skips_unparsable_versions() -> None:
    text = json.dumps({"dependencies": {"a": "github:user/repo", "b": "1.0.0"}})
    assert _names(dep.parse_package_json(text, "package.json")) == {"b"}


# ---------------- package-lock.json ----------------
def test_package_lock_v3() -> None:
    text = json.dumps({"packages": {
        "": {"name": "root", "version": "1.0.0"},
        "node_modules/lodash": {"version": "4.17.21"},
        "node_modules/jest": {"version": "29.7.0", "dev": True},
    }})
    comps = _by_name(dep.parse_package_lock(text, "package-lock.json"))

    assert comps["lodash"].version == "4.17.21"
    assert comps["jest"].scope == "dev"
    assert "" not in comps        # ルートエントリは無視


def test_package_lock_v1_walks_nested_dependencies() -> None:
    text = json.dumps({"dependencies": {
        "a": {"version": "1.0.0", "dependencies": {"b": {"version": "2.0.0"}}},
        "c": {"version": "3.0.0", "dev": True},
    }})
    comps = _by_name(dep.parse_package_lock(text, "package-lock.json"))

    assert comps["a"].version == "1.0.0"
    assert comps["b"].version == "2.0.0"   # 入れ子も拾う
    assert comps["c"].scope == "dev"


def test_package_lock_dedupes_same_name_version() -> None:
    text = json.dumps({"packages": {
        "node_modules/a": {"version": "1.0.0"},
        "node_modules/b/node_modules/a": {"version": "1.0.0"},
    }})
    assert len(dep.parse_package_lock(text, "package-lock.json")) == 1


# ---------------- yarn.lock ----------------
def test_yarn_lock() -> None:
    text = (
        'lodash@^4.17.20:\n  version "4.17.21"\n  resolved "https://..."\n\n'
        '"@babel/core@^7.0.0":\n  version "7.23.0"\n'
    )
    comps = _by_name(dep.parse_yarn_lock(text, "yarn.lock"))
    assert comps["lodash"].version == "4.17.21"
    assert comps["@babel/core"].version == "7.23.0"


# ---------------- requirements.txt ----------------
def test_requirements_only_pinned() -> None:
    text = "flask==2.0.1\n# comment\n\nrequests>=2.0\n-r other.txt\nDjango==4.2.1 ; python_version>'3'\n"
    comps = _by_name(dep.parse_requirements(text, "requirements.txt"))

    assert comps["flask"].version == "2.0.1"
    assert comps["django"].version == "4.2.1"   # 名前は小文字化
    assert "requests" not in comps              # ピン留めされていない行は無視


# ---------------- poetry.lock ----------------
def test_poetry_lock() -> None:
    text = (
        '[[package]]\nname = "flask"\nversion = "2.0.1"\ncategory = "main"\n\n'
        '[[package]]\nname = "pytest"\nversion = "7.4.0"\ncategory = "dev"\n'
    )
    comps = _by_name(dep.parse_poetry_lock(text, "poetry.lock"))
    assert comps["flask"].version == "2.0.1"
    assert comps["flask"].scope == "runtime"
    assert comps["pytest"].scope == "dev"


def test_poetry_lock_ignores_preamble() -> None:
    """先頭の [metadata] 等を package として拾わない。"""
    text = '[metadata]\nname = "not-a-package"\nversion = "9.9.9"\n\n[[package]]\nname = "a"\nversion = "1.0"\n'
    assert _names(dep.parse_poetry_lock(text, "poetry.lock")) == {"a"}


# ---------------- Pipfile.lock ----------------
def test_pipfile_lock() -> None:
    text = json.dumps({
        "default": {"flask": {"version": "==2.0.1"}},
        "develop": {"pytest": {"version": "==7.4.0"}},
    })
    comps = _by_name(dep.parse_pipfile_lock(text, "Pipfile.lock"))
    assert comps["flask"].version == "2.0.1"
    assert comps["pytest"].scope == "dev"


# ---------------- go.mod ----------------
def test_go_mod() -> None:
    text = (
        "module example.com/m\n\ngo 1.21\n\n"
        "require (\n\tgithub.com/pkg/errors v0.9.1\n\tgolang.org/x/net v0.17.0\n)\n"
        "require github.com/single/dep v1.2.3\n"
    )
    comps = _by_name(dep.parse_go_mod(text, "go.mod"))
    assert comps["github.com/pkg/errors"].version == "v0.9.1"
    assert comps["golang.org/x/net"].version == "v0.17.0"
    assert comps["github.com/single/dep"].version == "v1.2.3"
    assert "module" not in comps


# ---------------- バージョン正規化 ----------------
@pytest.mark.parametrize(
    ("raw", "expected"),
    [("^4.17.20", "4.17.20"), ("~1.2", "1.2"), (">=2.0.0", "2.0.0"),
     ('"3.1.4"', "3.1.4"), ("1.0.0-beta.1", "1.0.0-beta.1"),
     ("latest", ""), ("*", ""), ("", "")],
)
def test_clean_version(raw: str, expected: str) -> None:
    assert dep._clean_version(raw) == expected


# ---------------- ロックファイル優先 ----------------
def test_lock_file_wins_over_manifest_in_same_dir() -> None:
    results = [
        dep.ManifestResult("app", dep.KIND_NPM_LOCK,
                           dep.parse_package_lock(json.dumps(
                               {"packages": {"node_modules/lodash": {"version": "4.17.21"}}}),
                               "app/package-lock.json")),
        dep.ManifestResult("app", dep.KIND_NPM_MANIFEST,
                           dep.parse_package_json(json.dumps(
                               {"dependencies": {"lodash": "^4.17.0"}}), "app/package.json")),
    ]
    comps = dep.resolve(results)
    assert [(c.name, c.version) for c in comps] == [("lodash", "4.17.21")]


def test_manifest_used_when_no_lock_in_that_dir() -> None:
    results = [
        dep.ManifestResult("app", dep.KIND_NPM_LOCK, [], ),
        dep.ManifestResult("other", dep.KIND_NPM_MANIFEST,
                           dep.parse_package_json(json.dumps(
                               {"dependencies": {"react": "18.0.0"}}), "other/package.json")),
    ]
    assert _names(dep.resolve(results)) == {"react"}


def test_python_and_npm_locks_are_independent() -> None:
    """同じディレクトリの poetry.lock は package.json を抑制しない。"""
    results = [
        dep.ManifestResult("app", dep.KIND_PY_LOCK,
                           dep.parse_poetry_lock('[[package]]\nname = "flask"\nversion = "2.0.1"\n',
                                                 "app/poetry.lock")),
        dep.ManifestResult("app", dep.KIND_NPM_MANIFEST,
                           dep.parse_package_json(json.dumps(
                               {"dependencies": {"react": "18.0.0"}}), "app/package.json")),
    ]
    assert _names(dep.resolve(results)) == {"flask", "react"}


def test_resolve_dedupes_across_files() -> None:
    results = [
        dep.ManifestResult("a", dep.KIND_GO, dep.parse_go_mod("require example.com/x v1.0.0", "a/go.mod")),
        dep.ManifestResult("b", dep.KIND_GO, dep.parse_go_mod("require example.com/x v1.0.0", "b/go.mod")),
    ]
    assert len(dep.resolve(results)) == 1


def test_applies_to_recognises_manifests(entry_factory) -> None:
    assert dep.applies_to(entry_factory("package.json", "{}"))
    assert dep.applies_to(entry_factory("go.mod", ""))
    assert not dep.applies_to(entry_factory("main.py", ""))
