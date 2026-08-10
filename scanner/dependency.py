"""依存関係・SBOMスキャナ。

各種マニフェスト/ロックファイルを解析してコンポーネント一覧(SBOM)を作り、
OSV.dev API で既知脆弱性を照合する。ネットワークが無い場合はSBOMのみ返す。
"""
from __future__ import annotations

import json
import os
import re
import urllib.request
import urllib.error
from typing import Dict, List, Tuple

from .models import Finding, Component
from .util import walk_files, rel, read_text
from . import cvss

OSV_BATCH_URL = "https://api.osv.dev/v1/querybatch"
OSV_VULN_URL = "https://api.osv.dev/v1/vulns/"
HTTP_TIMEOUT = 20


# ------------------------- マニフェスト解析 -------------------------
def _clean_version(v: str) -> str:
    if not v:
        return ""
    v = v.strip().strip('"\'')
    # レンジ記号を除去して代表バージョンを得る
    v = re.sub(r"^[\^~>=<\s]+", "", v)
    m = re.match(r"(\d+\.\d+(?:\.\d+)?(?:[-.][0-9A-Za-z.]+)?)", v)
    return m.group(1) if m else ""


def parse_package_json(text, relpath, comps):
    try:
        data = json.loads(text)
    except Exception:
        return
    for scope, key in (("runtime", "dependencies"), ("dev", "devDependencies")):
        for name, ver in (data.get(key) or {}).items():
            cv = _clean_version(str(ver))
            if cv:
                comps.append(Component(name=name, version=cv, ecosystem="npm", file=relpath, scope=scope))


def parse_package_lock(text, relpath, comps):
    try:
        data = json.loads(text)
    except Exception:
        return
    seen = set()
    if "packages" in data:  # lockfile v2/v3
        for pkgpath, meta in data["packages"].items():
            if not pkgpath or "version" not in meta:
                continue
            name = pkgpath.split("node_modules/")[-1]
            if not name:
                continue
            scope = "dev" if meta.get("dev") else "runtime"
            k = (name, meta["version"])
            if k in seen:
                continue
            seen.add(k)
            comps.append(Component(name=name, version=meta["version"], ecosystem="npm", file=relpath, scope=scope))
    elif "dependencies" in data:  # lockfile v1
        def walk(deps, scope):
            for name, meta in deps.items():
                ver = meta.get("version", "")
                if ver:
                    k = (name, ver)
                    if k not in seen:
                        seen.add(k)
                        comps.append(Component(name=name, version=_clean_version(ver), ecosystem="npm", file=relpath, scope=scope))
                if "dependencies" in meta:
                    walk(meta["dependencies"], scope)
        walk(data["dependencies"], "runtime")


def parse_yarn_lock(text, relpath, comps):
    blocks = re.split(r"\n(?=\S)", text)
    for b in blocks:
        header = b.split("\n", 1)[0]
        m = re.match(r'"?(@?[^@\s,"]+)@', header)
        vm = re.search(r'\n\s+version:?\s+"?([0-9][^"\s]*)"?', b)
        if m and vm:
            comps.append(Component(name=m.group(1), version=vm.group(1), ecosystem="npm", file=relpath, scope="runtime"))


def parse_requirements(text, relpath, comps):
    for line in text.splitlines():
        line = line.strip()
        if not line or line.startswith("#") or line.startswith("-"):
            continue
        m = re.match(r"([A-Za-z0-9_.\-]+)\s*==\s*([0-9][^\s;#]*)", line)
        if m:
            comps.append(Component(name=m.group(1).lower(), version=m.group(2), ecosystem="PyPI", file=relpath, scope="runtime"))


def parse_poetry_lock(text, relpath, comps):
    for block in text.split("[[package]]"):
        nm = re.search(r'name\s*=\s*"([^"]+)"', block)
        vm = re.search(r'version\s*=\s*"([^"]+)"', block)
        if nm and vm:
            comps.append(Component(name=nm.group(1).lower(), version=vm.group(1), ecosystem="PyPI", file=relpath, scope="runtime"))


def parse_pipfile_lock(text, relpath, comps):
    try:
        data = json.loads(text)
    except Exception:
        return
    for scope, key in (("runtime", "default"), ("dev", "develop")):
        for name, meta in (data.get(key) or {}).items():
            ver = _clean_version(str(meta.get("version", "")))
            if ver:
                comps.append(Component(name=name.lower(), version=ver, ecosystem="PyPI", file=relpath, scope=scope))


def parse_go_mod(text, relpath, comps):
    in_block = False
    for line in text.splitlines():
        s = line.strip()
        if s.startswith("require ("):
            in_block = True
            continue
        if in_block and s == ")":
            in_block = False
            continue
        m = re.match(r"(?:require\s+)?([\w./\-]+)\s+v([0-9][^\s/]*)", s)
        if m and ("." in m.group(1)):
            comps.append(Component(name=m.group(1), version="v" + m.group(2), ecosystem="Go", file=relpath, scope="runtime"))


def collect_components(root: str) -> List[Component]:
    comps: List[Component] = []
    lock_dirs_npm = set()
    lock_dirs_py = set()
    # 先にロックファイルを処理（正確なバージョン）、無ければマニフェスト
    manifests = []
    for path in walk_files(root):
        name = os.path.basename(path).lower()
        manifests.append((name, path, os.path.dirname(path)))

    for name, path, d in manifests:
        relpath = rel(root, path)
        text = read_text(path)
        if not text:
            continue
        if name == "package-lock.json":
            parse_package_lock(text, relpath, comps); lock_dirs_npm.add(d)
        elif name == "yarn.lock":
            parse_yarn_lock(text, relpath, comps); lock_dirs_npm.add(d)
        elif name == "poetry.lock":
            parse_poetry_lock(text, relpath, comps); lock_dirs_py.add(d)
        elif name == "pipfile.lock":
            parse_pipfile_lock(text, relpath, comps); lock_dirs_py.add(d)

    for name, path, d in manifests:
        relpath = rel(root, path)
        text = read_text(path)
        if not text:
            continue
        if name == "package.json" and d not in lock_dirs_npm:
            parse_package_json(text, relpath, comps)
        elif name in ("requirements.txt", "requirements-dev.txt") and d not in lock_dirs_py:
            parse_requirements(text, relpath, comps)
        elif name == "go.mod":
            parse_go_mod(text, relpath, comps)

    # 重複排除
    uniq: Dict[Tuple[str, str, str], Component] = {}
    for c in comps:
        uniq.setdefault((c.ecosystem, c.name, c.version), c)
    return list(uniq.values())


# ------------------------- OSV 照合 -------------------------
def _http_post(url, payload):
    data = json.dumps(payload).encode("utf-8")
    req = urllib.request.Request(url, data=data, headers={"Content-Type": "application/json"})
    with urllib.request.urlopen(req, timeout=HTTP_TIMEOUT) as r:
        return json.loads(r.read().decode("utf-8"))


def _http_get(url):
    req = urllib.request.Request(url, headers={"Accept": "application/json"})
    with urllib.request.urlopen(req, timeout=HTTP_TIMEOUT) as r:
        return json.loads(r.read().decode("utf-8"))


def _derive_severity(vuln: dict) -> str:
    # 1) database_specific severity ラベル
    for label in [
        (vuln.get("database_specific") or {}).get("severity"),
    ]:
        s = cvss.severity_from_label(label or "")
        if s:
            return s
    # 2) affected[].database_specific
    for aff in vuln.get("affected", []) or []:
        s = cvss.severity_from_label(((aff.get("database_specific") or {}).get("severity")) or "")
        if s:
            return s
    # 3) CVSSベクタ
    best = None
    for sv in vuln.get("severity", []) or []:
        if sv.get("type", "").startswith("CVSS"):
            sc = cvss.base_score(sv.get("score", ""))
            lab = cvss.score_to_severity(sc)
            if lab and (best is None or cvss.score_to_severity(sc)):
                best = lab
    return best or "MEDIUM"


def _fixed_version(vuln: dict, name: str) -> str:
    for aff in vuln.get("affected", []) or []:
        pkg = aff.get("package", {}) or {}
        if pkg.get("name", "").lower() != name.lower():
            continue
        for rng in aff.get("ranges", []) or []:
            for ev in rng.get("events", []) or []:
                if "fixed" in ev:
                    return ev["fixed"]
    return ""


def query_osv(components: List[Component]) -> Tuple[List[Finding], bool]:
    findings: List[Finding] = []
    if not components:
        return findings, True

    queries = [{"version": c.version, "package": {"name": c.name, "ecosystem": c.ecosystem}} for c in components]
    try:
        # querybatch は最大1000件。分割送信。
        vuln_ids_per_comp: List[List[str]] = []
        for i in range(0, len(queries), 500):
            chunk = queries[i:i + 500]
            resp = _http_post(OSV_BATCH_URL, {"queries": chunk})
            for res in resp.get("results", []):
                ids = [v["id"] for v in (res.get("vulns") or [])]
                vuln_ids_per_comp.append(ids)
    except (urllib.error.URLError, urllib.error.HTTPError, TimeoutError, OSError, ValueError):
        return findings, False  # オフライン扱い

    # 詳細を取得（重複IDはキャッシュ）
    detail_cache: Dict[str, dict] = {}
    for comp, ids in zip(components, vuln_ids_per_comp):
        if not ids:
            continue
        comp_sevs = []
        for vid in ids:
            if vid not in detail_cache:
                try:
                    detail_cache[vid] = _http_get(OSV_VULN_URL + vid)
                except Exception:
                    detail_cache[vid] = {"id": vid}
            vuln = detail_cache[vid]
            sev = _derive_severity(vuln)
            comp_sevs.append(sev)
            summary = vuln.get("summary") or (vuln.get("details", "")[:160])
            aliases = vuln.get("aliases", []) or []
            cve = next((a for a in aliases if a.startswith("CVE-")), vid)
            fixed = _fixed_version(vuln, comp.name)
            refs = [r.get("url") for r in (vuln.get("references") or []) if r.get("url")][:5]
            refs.append(f"https://osv.dev/vulnerability/{vid}")
            findings.append(Finding(
                category="dependency", severity=sev,
                title=f"{comp.name} {comp.version}: {cve}",
                description=summary or "既知の脆弱性が報告されています。",
                recommendation=(f"{fixed} 以降へ更新してください。" if fixed else "修正版へのアップデートを検討してください。"),
                file=comp.file, package=comp.name, version=comp.version, ecosystem=comp.ecosystem,
                rule_id=vid, references=refs, fixed_version=fixed,
            ).finalize())
        # コンポーネント側に集計
        comp.vuln_count = len(ids)
        from .models import worst_severity
        comp.max_severity = worst_severity(comp_sevs) if comp_sevs else "INFO"
    return findings, True


def scan(root: str) -> Tuple[List[Finding], List[Component], bool]:
    components = collect_components(root)
    findings, online = query_osv(components)
    return findings, components, online
