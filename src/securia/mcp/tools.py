"""MCP から呼べる Securia のツール群。

設計の要は文脈の経済性。実リポジトリのスキャンは数百件の検出を出すので、
全件をそのまま返すと呼び出し側の文脈を食い潰す。scan は要約と上位数件だけを
返し、続きは絞り込みとページング付きの list_findings で取らせる。

各ツールは人間にもモデルにも読める簡潔なテキストを返す。JSON をそのまま
返すより行数が減り、fingerprint など後続操作に必要な識別子は残せる。
"""
from __future__ import annotations

import json
from collections.abc import Callable
from dataclasses import dataclass, field
from fnmatch import fnmatch
from pathlib import Path
from typing import Any

from ..config import Config
from ..diff import compare
from ..engine import run_scan
from ..models import SEVERITIES, Component, Finding, severity_rank
from ..osv import STATUS_DISABLED, STATUS_OFFLINE, OsvClient
from ..paths import PathNotAllowed, ensure_scannable, normalize
from ..scan import all_rule_ids
from ..scan.walker import read_snippet
from ..store import Store
from .protocol import optional_bool, optional_int, optional_str, require_str

MAX_LIMIT = 200
DEFAULT_SCAN_LIMIT = 20
DEFAULT_LIST_LIMIT = 30

_SEVERITY_ENUM = list(SEVERITIES)
_CATEGORY_ENUM = ["dependency", "static", "config"]


class ToolError(Exception):
    """ツール実行時のエラー。

    プロトコルエラーではなく isError:true の結果として返す。呼び出し側の
    モデルが内容を読んで、引数を直して呼び直せるようにするため。
    """


@dataclass
class Tool:
    name: str
    title: str
    description: str
    input_schema: dict
    handler: Callable[[dict], str]
    read_only: bool = True

    def to_spec(self) -> dict:
        return {
            "name": self.name,
            "title": self.title,
            "description": self.description,
            "inputSchema": self.input_schema,
            "annotations": {
                "title": self.title,
                "readOnlyHint": self.read_only,
                "destructiveHint": False,
                "openWorldHint": False,
            },
        }


@dataclass
class ToolRegistry:
    cfg: Config
    store: Store
    tools: dict[str, Tool] = field(default_factory=dict)

    def register(self, tool: Tool) -> None:
        self.tools[tool.name] = tool

    def list_specs(self) -> list[dict]:
        return [t.to_spec() for t in self.tools.values()]

    def call(self, name: str, arguments: dict) -> str:
        tool = self.tools.get(name)
        if tool is None:
            raise ToolError(f"ツール '{name}' はありません。使えるのは: {', '.join(self.tools)}")
        return tool.handler(arguments)


# ---------------- 共通ヘルパ ----------------
def _severity_arg(params: dict, key: str, default: str | None = None) -> str | None:
    raw = optional_str(params, key) or default
    if raw is None:
        return None
    value = raw.upper()
    if value not in SEVERITIES:
        raise ToolError(f"{key} は {'/'.join(SEVERITIES)} のいずれかです（受け取った値: {raw}）")
    return value


def _resolve_scan(store: Store, params: dict) -> dict:
    """scan_id → target の最新 → 全体の最新、の順に解決する。"""
    scan_id = optional_int(params, "scan_id", minimum=1)
    if scan_id is not None:
        scan = store.get_scan(scan_id)
        if scan is None:
            raise ToolError(f"スキャン ID {scan_id} は見つかりません。securia_scan_history で確認してください。")
        return scan

    target = optional_str(params, "target")
    if target:
        key = str(normalize(target))
        latest = store.latest_scan_id(key)
        if latest is None:
            raise ToolError(f"{key} のスキャン履歴がありません。先に securia_scan を実行してください。")
        return store.get_scan(latest)

    scans = store.list_scans(limit=1)
    if not scans:
        raise ToolError("スキャン履歴がありません。先に securia_scan を実行してください。")
    return scans[0]


def _filter_findings(findings: list[Finding], params: dict) -> list[Finding]:
    min_severity = _severity_arg(params, "min_severity")
    category = optional_str(params, "category")
    if category and category not in _CATEGORY_ENUM:
        raise ToolError(f"category は {'/'.join(_CATEGORY_ENUM)} のいずれかです（受け取った値: {category}）")
    rule_pattern = optional_str(params, "rule_id")
    file_substring = optional_str(params, "file")
    new_only = optional_bool(params, "new_only")
    include_suppressed = optional_bool(params, "include_suppressed")

    threshold = severity_rank(min_severity) if min_severity else -1

    out = []
    for f in findings:
        if not include_suppressed and f.suppressed:
            continue
        if threshold >= 0 and severity_rank(f.severity) < threshold:
            continue
        if category and f.category != category:
            continue
        if rule_pattern and not fnmatch(f.rule_id, rule_pattern):
            continue
        if file_substring and file_substring.lower() not in f.file.lower():
            continue
        if new_only and f.status != "new":
            continue
        out.append(f)
    return out


def _format_finding_line(f: Finding) -> str:
    flags = " NEW" if f.status == "new" else ""
    if f.suppressed:
        flags += " 抑制済み"
    if f.category == "dependency":
        fix = f" → {f.fixed_version}" if f.fixed_version else ""
        where = f"{f.package}@{f.version}{fix}"
    else:
        where = f"{f.file}:{f.line}" if f.line else f.file
    return f"{f.severity:<8} {f.rule_id:<26} {where}  [{f.fingerprint}]{flags}\n" \
           f"         {f.title}"


def _format_findings(findings: list[Finding], offset: int, limit: int, total: int,
                     scan_id: int, hint_tool: str) -> str:
    if not findings:
        return "条件に一致する検出はありません。"
    lines = [_format_finding_line(f) for f in findings]
    body = "\n".join(lines)
    shown_to = offset + len(findings)
    footer = ""
    if shown_to < total:
        footer = (f"\n\n{total} 件中 {offset + 1}〜{shown_to} 件を表示。続きは "
                  f"{hint_tool}(scan_id={scan_id}, offset={shown_to}) で取得できます。")
    return body + footer


def _severity_breakdown(counts: dict) -> str:
    return " / ".join(f"{sev} {counts.get(sev, 0)}" for sev in SEVERITIES if counts.get(sev, 0))


def _osv_note(status: str) -> str:
    if status == STATUS_OFFLINE:
        return "  ⚠ OSV に接続できず、依存関係の CVE 照合はスキップされました。"
    if status == STATUS_DISABLED:
        return "  ⓘ OSV 照合は無効です（設定または offline 指定）。"
    return ""


def _paginate(items: list, params: dict, default_limit: int) -> tuple[list, int, int]:
    offset = optional_int(params, "offset", default=0, minimum=0) or 0
    limit = optional_int(params, "limit", default=default_limit, minimum=1, maximum=MAX_LIMIT)
    return items[offset:offset + limit], offset, len(items)


# ---------------- 各ツールの実装 ----------------
def _tool_scan(cfg: Config, store: Store) -> Tool:
    def handler(params: dict) -> str:
        raw_path = require_str(params, "path")
        offline = optional_bool(params, "offline")
        save = optional_bool(params, "save", default=True)
        limit = optional_int(params, "limit", default=DEFAULT_SCAN_LIMIT, minimum=1, maximum=MAX_LIMIT)
        min_severity = _severity_arg(params, "min_severity")

        try:
            target = ensure_scannable(raw_path, cfg.scan.allowed_roots)
        except PathNotAllowed as e:
            raise ToolError(str(e)) from e

        key = str(target)
        previous_scan_id = store.latest_scan_id(key)
        suppressed = store.suppressed_fingerprints(key)
        osv_client = None if offline or not cfg.osv.enabled else OsvClient(cfg.osv, cache=store)

        result = run_scan(target, cfg, osv_client=osv_client, suppressed=suppressed)
        scan_diff = compare(store, previous_scan_id, result)
        scan_id = store.save_scan(result) if save else None

        summary = result.summary()
        head = [
            f"対象: {key}",
            f"  {summary['total_files']} ファイル / {summary['total_components']} コンポーネント / {result.elapsed_sec} 秒",
        ]
        note = _osv_note(result.osv_status)
        if note:
            head.append(note)
        head.append(
            f"  検出 {summary['total_findings']} 件"
            + (f"（抑制済み {summary['suppressed_findings']} 件は除外）" if summary["suppressed_findings"] else "")
        )
        if summary["total_findings"]:
            head.append("  " + _severity_breakdown(summary["severity_counts"]))
        if scan_diff.has_baseline:
            head.append(f"  前回比: 新規 {scan_diff.new_count} / 修正済み {scan_diff.fixed_count} "
                        f"/ 継続 {scan_diff.existing_count}")
        else:
            head.append("  前回比: 初回スキャン（比較対象なし）")
        if scan_id is not None:
            head.append(f"  scan_id: {scan_id}")

        shown = _filter_findings(result.findings, {"min_severity": min_severity} if min_severity else {})
        page = shown[:limit]

        parts = ["\n".join(head)]
        if page:
            label = f"検出（重要度順、{len(page)}/{len(shown)} 件）:" if min_severity is None else \
                    f"{min_severity} 以上の検出（{len(page)}/{len(shown)} 件）:"
            parts.append(label + "\n" + "\n".join(_format_finding_line(f) for f in page))
            if len(shown) > len(page) and scan_id is not None:
                parts.append(f"残り {len(shown) - len(page)} 件は "
                             f"securia_list_findings(scan_id={scan_id}, offset={len(page)}) で取得できます。")
        else:
            parts.append("検出はありませんでした。")

        if scan_diff.has_baseline and scan_diff.fixed:
            fixed_lines = [f"  {f.severity:<8} {f.rule_id:<26} {f.file}" for f in scan_diff.fixed[:10]]
            parts.append(f"前回から修正された検出（{len(scan_diff.fixed)} 件）:\n" + "\n".join(fixed_lines))

        return "\n\n".join(parts)

    return Tool(
        name="securia_scan",
        title="脆弱性スキャンを実行",
        description=(
            "指定ディレクトリを脆弱性スキャンする。依存関係(SBOM/OSV照合)・静的コード解析・"
            "設定ファイル診断を一度に実行し、要約と重要度の高い検出を返す。"
            "結果は保存され、2回目以降は前回との差分（新規/修正済み）が付く。"
            "全件が必要なときは戻り値の scan_id を securia_list_findings に渡すこと。"
        ),
        input_schema={
            "type": "object",
            "properties": {
                "path": {"type": "string", "description": "スキャン対象ディレクトリの絶対パス"},
                "min_severity": {"type": "string", "enum": _SEVERITY_ENUM,
                                 "description": "この重要度以上のみ表示する（既定: 全件）"},
                "limit": {"type": "integer", "minimum": 1, "maximum": MAX_LIMIT,
                          "description": f"表示する検出の最大件数（既定 {DEFAULT_SCAN_LIMIT}）"},
                "offline": {"type": "boolean",
                            "description": "OSV.dev へ問い合わせない。ネットワークを使わず、CVE 照合は行われない"},
                "save": {"type": "boolean", "description": "履歴 DB に保存する（既定 true）"},
            },
            "required": ["path"],
            "additionalProperties": False,
        },
        handler=handler,
        read_only=False,   # 履歴 DB に書き込む
    )


def _tool_list_findings(cfg: Config, store: Store) -> Tool:
    def handler(params: dict) -> str:
        scan = _resolve_scan(store, params)
        findings = store.load_findings(scan["id"])
        filtered = _filter_findings(findings, params)
        page, offset, total = _paginate(filtered, params, DEFAULT_LIST_LIMIT)

        header = f"scan_id={scan['id']}  対象: {scan['target']}  ({scan['scanned_at']})"
        body = _format_findings(page, offset, len(page), total, scan["id"], "securia_list_findings")
        return f"{header}\n\n{body}"

    return Tool(
        name="securia_list_findings",
        title="検出を絞り込んで一覧",
        description=(
            "保存済みスキャンの検出を、重要度・種別・ルール・ファイル・新規かどうかで絞り込んで一覧する。"
            "scan_id も target も省略すると直近のスキャンを対象にする。"
            "1件の詳細（説明・対応方法・該当コード）は securia_get_finding で取得する。"
        ),
        input_schema={
            "type": "object",
            "properties": {
                "scan_id": {"type": "integer", "minimum": 1, "description": "対象のスキャン ID"},
                "target": {"type": "string", "description": "対象ディレクトリ（その最新スキャンを使う）"},
                "min_severity": {"type": "string", "enum": _SEVERITY_ENUM},
                "category": {"type": "string", "enum": _CATEGORY_ENUM,
                             "description": "dependency=依存関係 / static=静的解析 / config=設定診断"},
                "rule_id": {"type": "string", "description": "ルール ID。glob 可（例: secret.*）"},
                "file": {"type": "string", "description": "ファイルパスの部分一致"},
                "new_only": {"type": "boolean", "description": "前回スキャンから増えたものだけ"},
                "include_suppressed": {"type": "boolean", "description": "抑制済みも含める"},
                "offset": {"type": "integer", "minimum": 0},
                "limit": {"type": "integer", "minimum": 1, "maximum": MAX_LIMIT,
                          "description": f"既定 {DEFAULT_LIST_LIMIT}"},
            },
            "additionalProperties": False,
        },
        handler=handler,
    )


def _tool_get_finding(cfg: Config, store: Store) -> Tool:
    def handler(params: dict) -> str:
        fingerprint = require_str(params, "fingerprint")
        scan = _resolve_scan(store, params)
        context = optional_int(params, "context_lines", default=4, minimum=0, maximum=30) or 0

        matches = [f for f in store.load_findings(scan["id"]) if f.fingerprint == fingerprint]
        if not matches:
            raise ToolError(
                f"fingerprint {fingerprint} は scan_id={scan['id']} に見つかりません。"
                "securia_list_findings で正しい値を確認してください。"
            )

        f = matches[0]
        lines = [
            f"{f.severity}  {f.title}",
            f"  ルール: {f.rule_id}",
            f"  種別: {f.category}",
            f"  fingerprint: {f.fingerprint}",
            f"  状態: {'新規' if f.status == 'new' else '継続'}{'（抑制済み）' if f.suppressed else ''}",
        ]
        if f.category == "dependency":
            lines.append(f"  パッケージ: {f.package} {f.version} ({f.ecosystem})")
            lines.append(f"  修正版: {f.fixed_version or '不明'}")
            lines.append(f"  検出元: {f.file}")
        else:
            lines.append(f"  場所: {f.file}:{f.line}" if f.line else f"  場所: {f.file}")
        if len(matches) > 1:
            lines.append(f"  同一 fingerprint の検出が {len(matches)} 箇所あります"
                         f"（行: {', '.join(str(m.line) for m in matches)}）")

        parts = ["\n".join(lines)]
        if f.description:
            parts.append(f"説明:\n  {f.description}")
        if f.recommendation:
            parts.append(f"対応:\n  {f.recommendation}")

        snippet = _load_snippet(cfg, scan["target"], f, context)
        if snippet:
            parts.append(snippet)

        if f.references:
            parts.append("参照:\n" + "\n".join(f"  {url}" for url in f.references))

        parts.append(
            "誤検知であれば securia_suppress("
            f"target=\"{scan['target']}\", fingerprint=\"{f.fingerprint}\") で次回以降の集計から外せます。"
        )
        return "\n\n".join(parts)

    return Tool(
        name="securia_get_finding",
        title="検出1件の詳細",
        description=(
            "検出1件の詳細を返す。説明・対応方法・参照 URL に加えて、"
            "該当箇所のソースコードをファイルから読んで前後の行とともに表示する。"
        ),
        input_schema={
            "type": "object",
            "properties": {
                "fingerprint": {"type": "string", "description": "securia_list_findings が返す [] 内の値"},
                "scan_id": {"type": "integer", "minimum": 1},
                "target": {"type": "string"},
                "context_lines": {"type": "integer", "minimum": 0, "maximum": 30,
                                  "description": "該当行の前後に表示する行数（既定 4）"},
            },
            "required": ["fingerprint"],
            "additionalProperties": False,
        },
        handler=handler,
    )


def _load_snippet(cfg: Config, target: str, finding: Finding, context: int) -> str:
    """該当箇所をファイルから読む。DB には生のコードを持たないため都度読む。"""
    if not finding.file or finding.line <= 0 or context == 0:
        return ""
    try:
        root = ensure_scannable(target, cfg.scan.allowed_roots)
    except PathNotAllowed:
        return ""

    candidate = normalize(root / finding.file)
    try:
        candidate.relative_to(root)          # 対象ディレクトリの外は読まない
    except ValueError:
        return ""
    if not candidate.is_file():
        return f"該当コード: {finding.file} は現在存在しません（移動または削除された可能性）。"

    rows = read_snippet(candidate, finding.line, context=context)
    if not rows:
        return ""
    width = max(len(str(r["line"])) for r in rows)
    body = "\n".join(
        f"  {'>' if r['target'] else ' '} {str(r['line']).rjust(width)} | {r['text']}" for r in rows
    )
    return f"該当コード ({finding.file}):\n{body}"


def _tool_list_components(cfg: Config, store: Store) -> Tool:
    def handler(params: dict) -> str:
        scan = _resolve_scan(store, params)
        components: list[Component] = store.load_components(scan["id"])
        if optional_bool(params, "vulnerable_only"):
            components = [c for c in components if c.vuln_count > 0]
        ecosystem = optional_str(params, "ecosystem")
        if ecosystem:
            components = [c for c in components if c.ecosystem.lower() == ecosystem.lower()]
        name_filter = optional_str(params, "name")
        if name_filter:
            components = [c for c in components if name_filter.lower() in c.name.lower()]

        components.sort(key=lambda c: (-severity_rank(c.max_severity), -c.vuln_count, c.name))
        page, offset, total = _paginate(components, params, DEFAULT_LIST_LIMIT)

        header = f"scan_id={scan['id']}  対象: {scan['target']}"
        if not page:
            return f"{header}\n\n条件に一致するコンポーネントはありません。"

        rows = []
        for c in page:
            vulns = f"{c.vuln_count} 件 ({c.max_severity})" if c.vuln_count else "なし"
            rows.append(f"{c.ecosystem:<6} {c.name:<32} {c.version:<14} {c.scope:<8} 脆弱性 {vulns}")
        footer = ""
        if offset + len(page) < total:
            footer = (f"\n\n{total} 件中 {offset + 1}〜{offset + len(page)} 件。続きは "
                      f"securia_list_components(scan_id={scan['id']}, offset={offset + len(page)})。")
        return f"{header}\n\n" + "\n".join(rows) + footer

    return Tool(
        name="securia_list_components",
        title="SBOM（依存コンポーネント）を一覧",
        description=(
            "スキャンで検出された依存コンポーネント（SBOM）を一覧する。"
            "脆弱性の有無・エコシステム・名前で絞り込める。"
        ),
        input_schema={
            "type": "object",
            "properties": {
                "scan_id": {"type": "integer", "minimum": 1},
                "target": {"type": "string"},
                "vulnerable_only": {"type": "boolean", "description": "CVE が報告されたものだけ"},
                "ecosystem": {"type": "string", "description": "npm / PyPI / Go など"},
                "name": {"type": "string", "description": "パッケージ名の部分一致"},
                "offset": {"type": "integer", "minimum": 0},
                "limit": {"type": "integer", "minimum": 1, "maximum": MAX_LIMIT},
            },
            "additionalProperties": False,
        },
        handler=handler,
    )


def _tool_scan_history(cfg: Config, store: Store) -> Tool:
    def handler(params: dict) -> str:
        target = optional_str(params, "target")
        key = str(normalize(target)) if target else None
        limit = optional_int(params, "limit", default=20, minimum=1, maximum=MAX_LIMIT)
        scans = store.list_scans(key, limit)
        if not scans:
            return "スキャン履歴はありません。securia_scan で最初のスキャンを実行してください。"

        rows = []
        for s in scans:
            counts = s["summary"]["severity_counts"]
            rows.append(
                f"scan_id={s['id']:<5} {s['scanned_at']}  検出 {s['summary']['total_findings']:>4} 件"
                f"  (CRIT {counts.get('CRITICAL', 0)} / HIGH {counts.get('HIGH', 0)})  {s['target']}"
            )
        return "\n".join(rows)

    return Tool(
        name="securia_scan_history",
        title="スキャン履歴",
        description="過去のスキャンを新しい順に一覧する。scan_id を得て他のツールに渡すために使う。",
        input_schema={
            "type": "object",
            "properties": {
                "target": {"type": "string", "description": "対象ディレクトリで絞り込む"},
                "limit": {"type": "integer", "minimum": 1, "maximum": MAX_LIMIT},
            },
            "additionalProperties": False,
        },
        handler=handler,
    )


def _tool_suppress(cfg: Config, store: Store) -> Tool:
    def handler(params: dict) -> str:
        fingerprint = require_str(params, "fingerprint")
        reason = optional_str(params, "reason") or ""
        target_arg = optional_str(params, "target")

        if target_arg:
            key = str(normalize(target_arg))
        else:
            scan = _resolve_scan(store, params)
            key = scan["target"]

        latest = store.latest_scan_id(key)
        match = None
        if latest is not None:
            match = next((f for f in store.load_findings(latest) if f.fingerprint == fingerprint), None)
        if match is None:
            raise ToolError(
                f"fingerprint {fingerprint} は {key} の最新スキャンに見つかりません。"
                "対象と fingerprint を securia_list_findings で確認してください。"
            )

        store.suppress(key, match, reason=reason)
        return (f"抑制しました: {match.rule_id}  {match.file}  [{fingerprint}]\n"
                f"  対象: {key}\n"
                f"  理由: {reason or '(なし)'}\n"
                "次回スキャンから集計に含まれなくなります。解除は securia_unsuppress。")

    return Tool(
        name="securia_suppress",
        title="検出を抑制（誤検知を消す）",
        description=(
            "誤検知と判断した検出を抑制し、以降の集計から外す。対象ディレクトリ単位で効くので、"
            "別プロジェクトの同じパターンは消えない。取り消しは securia_unsuppress。"
            "抑制する前に securia_get_finding で該当コードを読み、本当に誤検知か確かめること。"
        ),
        input_schema={
            "type": "object",
            "properties": {
                "fingerprint": {"type": "string"},
                "target": {"type": "string", "description": "対象ディレクトリ（省略時は直近スキャンの対象）"},
                "reason": {"type": "string", "description": "なぜ誤検知と判断したか"},
            },
            "required": ["fingerprint"],
            "additionalProperties": False,
        },
        handler=handler,
        read_only=False,
    )


def _tool_unsuppress(cfg: Config, store: Store) -> Tool:
    def handler(params: dict) -> str:
        fingerprint = require_str(params, "fingerprint")
        target_arg = optional_str(params, "target")
        key = str(normalize(target_arg)) if target_arg else _resolve_scan(store, params)["target"]

        if not store.unsuppress(key, fingerprint):
            raise ToolError(f"{key} に fingerprint {fingerprint} の抑制はありません。")
        return f"抑制を解除しました: [{fingerprint}]  対象: {key}"

    return Tool(
        name="securia_unsuppress",
        title="抑制を解除",
        description="抑制した検出を元に戻し、次回スキャンから再び集計に含める。",
        input_schema={
            "type": "object",
            "properties": {
                "fingerprint": {"type": "string"},
                "target": {"type": "string"},
            },
            "required": ["fingerprint"],
            "additionalProperties": False,
        },
        handler=handler,
        read_only=False,
    )


def _tool_list_suppressions(cfg: Config, store: Store) -> Tool:
    def handler(params: dict) -> str:
        target = optional_str(params, "target")
        key = str(normalize(target)) if target else None
        rows = store.list_suppressions(key)
        if not rows:
            return "抑制された検出はありません。"
        return "\n".join(
            f"[{r['fingerprint']}] {r['rule_id'] or '-':<26} {r['file'] or '-'}"
            + (f"\n         理由: {r['reason']}" if r["reason"] else "")
            + (f"\n         対象: {r['target']}" if key is None else "")
            for r in rows
        )

    return Tool(
        name="securia_list_suppressions",
        title="抑制の一覧",
        description="抑制中の検出を一覧する。対象ディレクトリで絞り込める。",
        input_schema={
            "type": "object",
            "properties": {"target": {"type": "string"}},
            "additionalProperties": False,
        },
        handler=handler,
    )


def _tool_list_rules(cfg: Config, store: Store) -> Tool:
    def handler(params: dict) -> str:
        pattern = optional_str(params, "pattern")
        rules = all_rule_ids()
        if pattern:
            rules = [r for r in rules if fnmatch(r, pattern)]
        if not rules:
            return f"パターン '{pattern}' に一致するルールはありません。"

        disabled = {r for r in rules if cfg.rules.is_disabled(r)}
        lines = []
        for rule_id in rules:
            marks = []
            if rule_id in disabled:
                marks.append("無効")
            override = cfg.rules.severity_for(rule_id, "")
            if override:
                marks.append(f"重要度上書き={override}")
            lines.append(rule_id + (f"  ({', '.join(marks)})" if marks else ""))

        note = ("\n\n依存関係の検出は OSV の CVE 番号がそのままルール ID になるため、"
                "この一覧には含まれません。")
        return "\n".join(lines) + note

    return Tool(
        name="securia_list_rules",
        title="検出ルールの一覧",
        description=(
            "静的コード解析と設定ファイル診断のルール ID を一覧する。"
            "設定で無効化・重要度変更されているものにはその旨が付く。"
        ),
        input_schema={
            "type": "object",
            "properties": {"pattern": {"type": "string", "description": "glob（例: secret.* / docker.*）"}},
            "additionalProperties": False,
        },
        handler=handler,
    )


def build_registry(cfg: Config, store: Store) -> ToolRegistry:
    registry = ToolRegistry(cfg=cfg, store=store)
    for factory in (
        _tool_scan,
        _tool_list_findings,
        _tool_get_finding,
        _tool_list_components,
        _tool_scan_history,
        _tool_suppress,
        _tool_unsuppress,
        _tool_list_suppressions,
        _tool_list_rules,
    ):
        registry.register(factory(cfg, store))
    return registry


# ---------------- リソース ----------------
def list_resources(cfg: Config, store: Store) -> list[dict]:
    resources = [{
        "uri": "securia://rules",
        "name": "検出ルール一覧",
        "description": "静的解析と設定診断のルール ID（設定による無効化・重要度上書きを反映）",
        "mimeType": "text/plain",
    }]
    for scan in store.list_scans(limit=10):
        resources.append({
            "uri": f"securia://scans/{scan['id']}",
            "name": f"スキャン #{scan['id']}: {Path(scan['target']).name}",
            "description": f"{scan['scanned_at']} / 検出 {scan['summary']['total_findings']} 件 / {scan['target']}",
            "mimeType": "application/json",
        })
    return resources


def list_resource_templates() -> list[dict]:
    return [{
        "uriTemplate": "securia://scans/{scan_id}",
        "name": "スキャン結果",
        "description": "保存済みスキャンの完全な結果（検出・SBOM・要約）を JSON で返す",
        "mimeType": "application/json",
    }]


def read_resource(cfg: Config, store: Store, uri: str) -> dict:
    """resources/read の contents 要素を1件返す。"""
    if uri == "securia://rules":
        return {"uri": uri, "mimeType": "text/plain", "text": "\n".join(all_rule_ids())}

    prefix = "securia://scans/"
    if uri.startswith(prefix):
        raw_id = uri[len(prefix):]
        if not raw_id.isdigit():
            raise ToolError(f"スキャン ID が不正です: {raw_id}")
        scan = store.get_scan(int(raw_id))
        if scan is None:
            raise ToolError(f"スキャン {raw_id} は見つかりません。")

        payload: dict[str, Any] = {
            **scan,
            "findings": [f.to_dict() for f in store.load_findings(scan["id"])],
            "components": [c.to_dict() for c in store.load_components(scan["id"])],
        }
        return {"uri": uri, "mimeType": "application/json",
                "text": json.dumps(payload, ensure_ascii=False, indent=2)}

    raise ToolError(f"未知のリソース URI です: {uri}")
