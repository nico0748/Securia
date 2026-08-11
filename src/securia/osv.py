"""OSV.dev クライアント。

以前は脆弱性 ID ごとに逐次 HTTP GET していたため、依存が多いリポジトリでは
往復回数がそのまま待ち時間になっていた。ここではスレッドプールで並列化し、
取得済みの脆弱性レコードは TTL 付きでキャッシュする。

ネットワークに出るのはパッケージ名とバージョンだけで、コードは送らない。
"""
from __future__ import annotations

import json
import re
import urllib.error
import urllib.request
from collections.abc import Callable
from concurrent.futures import ThreadPoolExecutor, as_completed
from threading import Event
from typing import Any, Protocol

from .config import OsvConfig
from .models import Component, Finding, severity_rank, worst_severity
from .scan import cvss

OSV_BATCH_URL = "https://api.osv.dev/v1/querybatch"
OSV_VULN_URL = "https://api.osv.dev/v1/vulns/"

BATCH_CHUNK = 500      # querybatch の1リクエストあたり件数
MAX_PAGES = 10         # 1クエリあたりのページング上限（暴走防止）

STATUS_OK = "ok"
STATUS_OFFLINE = "offline"
STATUS_DISABLED = "disabled"


class OsvUnavailable(Exception):
    """OSV に到達できなかった。オフライン扱いにする。"""


class VulnCache(Protocol):
    def get_vuln(self, vuln_id: str, ttl_days: int) -> dict | None: ...
    def put_vuln(self, vuln_id: str, data: dict) -> None: ...


ProgressFn = Callable[[str, int, int], None]


def _default_post(url: str, payload: dict, timeout: float) -> dict:
    data = json.dumps(payload).encode("utf-8")
    req = urllib.request.Request(url, data=data, headers={"Content-Type": "application/json"})
    with urllib.request.urlopen(req, timeout=timeout) as r:  # noqa: S310 (URL は定数)
        return json.loads(r.read().decode("utf-8"))


def _default_get(url: str, timeout: float) -> dict:
    req = urllib.request.Request(url, headers={"Accept": "application/json"})
    with urllib.request.urlopen(req, timeout=timeout) as r:  # noqa: S310
        return json.loads(r.read().decode("utf-8"))


class OsvClient:
    """OSV への問い合わせと Finding への変換。

    post/get を差し替えられるようにしてあるのは、ネットワーク無しで
    テストするため。
    """

    def __init__(
        self,
        cfg: OsvConfig,
        cache: VulnCache | None = None,
        post: Callable[[str, dict, float], dict] | None = None,
        get: Callable[[str, float], dict] | None = None,
    ) -> None:
        self.cfg = cfg
        self.cache = cache
        self._post_fn = post or _default_post
        self._get_fn = get or _default_get

    # ---------------- 公開 API ----------------
    def enrich(
        self,
        components: list[Component],
        progress: ProgressFn | None = None,
        cancel: Event | None = None,
    ) -> tuple[list[Finding], str]:
        """コンポーネント一覧に脆弱性情報を付け、Finding を返す。

        components の vuln_count / max_severity はこの中で更新される。
        戻り値の2つ目は STATUS_OK / STATUS_OFFLINE / STATUS_DISABLED。
        """
        if not self.cfg.enabled:
            return [], STATUS_DISABLED
        if not components:
            return [], STATUS_OK

        try:
            ids_per_component = self._query_batch(components, cancel)
        except OsvUnavailable:
            return [], STATUS_OFFLINE

        unique_ids = sorted({vid for ids in ids_per_component for vid in ids})
        if not unique_ids:
            return [], STATUS_OK

        details = self._fetch_details(unique_ids, progress, cancel)

        findings: list[Finding] = []
        for comp, ids in zip(components, ids_per_component, strict=True):
            if not ids:
                continue
            raw = [
                self._to_finding(comp, vid, details[vid])
                for vid in ids
                if vid in details
            ]
            merged = merge_advisories(raw)
            findings.extend(merged)
            comp.vuln_count = len(merged)
            comp.max_severity = worst_severity([f.severity for f in merged]) if merged else "INFO"
        return findings, STATUS_OK

    # ---------------- 内部 ----------------
    def _query_batch(self, components: list[Component], cancel: Event | None) -> list[list[str]]:
        """querybatch で各コンポーネントの脆弱性 ID を引く。順序は components と一致。"""
        queries = [
            {"version": c.version, "package": {"name": c.name, "ecosystem": c.ecosystem}}
            for c in components
        ]
        ids_per_query: list[list[str]] = [[] for _ in queries]

        for start in range(0, len(queries), BATCH_CHUNK):
            chunk_offset = start
            pending: dict[int, dict[str, Any]] = {
                i: dict(q) for i, q in enumerate(queries[start:start + BATCH_CHUNK])
            }
            for _page in range(MAX_PAGES):
                if not pending:
                    break
                if cancel is not None and cancel.is_set():
                    return ids_per_query
                indices = list(pending.keys())
                payload = {"queries": [pending[i] for i in indices]}
                try:
                    resp = self._post_fn(OSV_BATCH_URL, payload, self.cfg.timeout)
                except (urllib.error.URLError, urllib.error.HTTPError, TimeoutError, OSError, ValueError) as e:
                    raise OsvUnavailable(str(e)) from e

                results = resp.get("results") or []
                next_pending: dict[int, dict[str, Any]] = {}
                for local_idx, res in zip(indices, results, strict=False):
                    vulns = res.get("vulns") or []
                    ids_per_query[chunk_offset + local_idx].extend(
                        v["id"] for v in vulns if isinstance(v, dict) and "id" in v
                    )
                    token = res.get("next_page_token")
                    if token:
                        follow = dict(pending[local_idx])
                        follow["page_token"] = token
                        next_pending[local_idx] = follow
                pending = next_pending

        return ids_per_query

    def _fetch_details(
        self, vuln_ids: list[str], progress: ProgressFn | None, cancel: Event | None
    ) -> dict[str, dict]:
        """脆弱性レコードの詳細を取る。キャッシュ済みは読まずに済ませる。"""
        out: dict[str, dict] = {}
        missing: list[str] = []

        for vid in vuln_ids:
            cached = self.cache.get_vuln(vid, self.cfg.cache_ttl_days) if self.cache else None
            if cached is not None:
                out[vid] = cached
            else:
                missing.append(vid)

        total = len(vuln_ids)
        done = total - len(missing)
        if progress:
            progress("脆弱性情報を取得中", done, total)

        if not missing:
            return out

        workers = max(1, min(self.cfg.max_workers, len(missing)))
        with ThreadPoolExecutor(max_workers=workers) as pool:
            futures = {
                pool.submit(self._get_fn, OSV_VULN_URL + vid, self.cfg.timeout): vid
                for vid in missing
            }
            for fut in as_completed(futures):
                vid = futures[fut]
                if cancel is not None and cancel.is_set():
                    for f in futures:
                        f.cancel()
                    break
                try:
                    data = fut.result()
                except Exception:  # noqa: BLE001 — 1件の失敗で全体を落とさない
                    data = None
                if data is not None:
                    out[vid] = data
                    if self.cache:
                        self.cache.put_vuln(vid, data)
                done += 1
                if progress:
                    progress("脆弱性情報を取得中", done, total)
        return out

    def _to_finding(self, comp: Component, vuln_id: str, vuln: dict) -> Finding:
        severity = derive_severity(vuln)
        summary = vuln.get("summary") or (vuln.get("details") or "")[:160]
        cve = canonical_id(vuln_id, vuln)
        fixed = fixed_version(vuln, comp.name)

        refs = [r.get("url") for r in (vuln.get("references") or []) if isinstance(r, dict) and r.get("url")][:5]
        refs.append(f"https://osv.dev/vulnerability/{vuln_id}")

        f = Finding(
            category="dependency",
            severity=severity,
            title=f"{comp.name} {comp.version}: {cve}",
            # 勧告 ID（CVE があればそれ）を rule_id にする。OSV のレコード ID を
            # そのまま使うと、同じ脆弱性が GHSA/PYSEC で別物になってしまう。
            rule_id=cve,
            description=summary or "既知の脆弱性が報告されています。",
            recommendation=(
                f"{fixed} 以降へ更新してください。" if fixed else "修正版へのアップデートを検討してください。"
            ),
            file=comp.file,
            package=comp.name,
            version=comp.version,
            ecosystem=comp.ecosystem,
            references=refs,
            fixed_version=fixed,
            evidence=cve,
        )
        f.compute_fingerprint()
        return f


def canonical_id(vuln_id: str, vuln: dict) -> str:
    """脆弱性の代表 ID。CVE 番号があればそれを使う。

    OSV は同一の脆弱性を GHSA-… と PYSEC-… の複数レコードで返すことがある。
    レコード ID をそのまま識別子にすると同じものが二重に数えられるので、
    共通の別名である CVE に寄せる。
    """
    for alias in vuln.get("aliases") or []:
        if isinstance(alias, str) and alias.startswith("CVE-"):
            return alias
    return vuln_id


_VERSION_RE = re.compile(r"^v?\d+(\.\d+)*([.\-+][0-9A-Za-z.\-]+)?$")
_SHA_RE = re.compile(r"^[0-9a-f]{7,40}$")


def _looks_like_version(value: str) -> bool:
    """`2.3.2` は版数、`70f906c51ce…` は git コミット。後者は利用者の役に立たない。"""
    if not value or _SHA_RE.match(value):
        return False
    return bool(_VERSION_RE.match(value))


def _version_key(value: str) -> tuple[int, ...]:
    parts = re.split(r"[.\-+]", value.lstrip("vV"))
    key: list[int] = []
    for p in parts[:4]:
        key.append(int(p) if p.isdigit() else 0)
    while len(key) < 4:
        key.append(0)
    return tuple(key)


def pick_fixed_version(candidates: list[str]) -> str:
    """複数の修正バージョンから、利用者が上げるべき最小の版を選ぶ。"""
    versions = [v for v in candidates if _looks_like_version(v)]
    if versions:
        return min(versions, key=_version_key)
    return next((v for v in candidates if v), "")


def merge_advisories(findings: list[Finding]) -> list[Finding]:
    """同じ勧告 ID を指す複数レコードを1件にまとめる。

    重要度は最も深刻なものを採る（データベース間で食い違うため、
    セキュリティツールとしては保守的な側に倒す）。修正バージョンは
    最小の版を採り、参照 URL は統合する。
    """
    groups: dict[str, list[Finding]] = {}
    order: list[str] = []
    for f in findings:
        if f.rule_id not in groups:
            groups[f.rule_id] = []
            order.append(f.rule_id)
        groups[f.rule_id].append(f)

    merged: list[Finding] = []
    for rule_id in order:
        group = groups[rule_id]
        if len(group) == 1:
            merged.append(group[0])
            continue

        base = max(group, key=lambda f: severity_rank(f.severity))
        base.severity = worst_severity([f.severity for f in group])
        base.fixed_version = pick_fixed_version([f.fixed_version for f in group])
        base.recommendation = (
            f"{base.fixed_version} 以降へ更新してください。"
            if base.fixed_version else "修正版へのアップデートを検討してください。"
        )
        # 説明は最も情報量の多いものを採る
        base.description = max((f.description for f in group), key=len)

        seen: set[str] = set()
        refs: list[str] = []
        for f in group:
            for url in f.references:
                if url not in seen:
                    seen.add(url)
                    refs.append(url)
        base.references = refs[:8]
        merged.append(base)
    return merged


def derive_severity(vuln: dict) -> str:
    """OSV レコードから重要度を決める。

    データベースごとに表現が違うので、
      1) トップレベルの database_specific.severity ラベル
      2) affected[].database_specific.severity ラベル
      3) CVSS ベクタから算出（複数あれば最も深刻なもの）
    の順に見る。どれも無ければ MEDIUM。
    """
    label = cvss.severity_from_label((vuln.get("database_specific") or {}).get("severity") or "")
    if label:
        return label

    for aff in vuln.get("affected") or []:
        if not isinstance(aff, dict):
            continue
        label = cvss.severity_from_label((aff.get("database_specific") or {}).get("severity") or "")
        if label:
            return label

    labels: list[str] = []
    for sv in vuln.get("severity") or []:
        if not isinstance(sv, dict) or not str(sv.get("type", "")).startswith("CVSS"):
            continue
        derived = cvss.score_to_severity(cvss.base_score(sv.get("score", "")))
        if derived:
            labels.append(derived)
    if labels:
        return worst_severity(labels)
    return "MEDIUM"


def fixed_version(vuln: dict, package_name: str) -> str:
    """該当パッケージの修正バージョンを取り出す。見つからなければ空文字。"""
    for aff in vuln.get("affected") or []:
        if not isinstance(aff, dict):
            continue
        pkg = aff.get("package") or {}
        if str(pkg.get("name", "")).lower() != package_name.lower():
            continue
        for rng in aff.get("ranges") or []:
            if not isinstance(rng, dict):
                continue
            for ev in rng.get("events") or []:
                if isinstance(ev, dict) and "fixed" in ev:
                    return str(ev["fixed"])
    return ""
