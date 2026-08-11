"""コマンドラインインターフェース。"""
from __future__ import annotations

import argparse
import json
import sys
from pathlib import Path

from . import __version__
from . import diff as diffmod
from .config import Config, ConfigError
from .engine import ScanResult, run_scan
from .models import SEVERITIES, severity_rank
from .osv import STATUS_DISABLED, STATUS_OFFLINE, OsvClient
from .paths import PathNotAllowed, ensure_scannable
from .scan import all_rule_ids
from .scan.walker import ScanCancelled
from .store import Store

EXIT_OK = 0
EXIT_FINDINGS = 1
EXIT_ERROR = 2


def _common_options(parser: argparse.ArgumentParser, *, suppress: bool) -> None:
    """全コマンド共通のオプション。

    サブコマンドの前後どちらに書いても効くよう、トップレベルと各サブパーサの
    両方に生やす。サブパーサ側は default=SUPPRESS にしておかないと、
    省略時に None でトップレベルの指定を上書きしてしまう。
    """
    kwargs = {"default": argparse.SUPPRESS} if suppress else {}
    parser.add_argument(
        "--config", metavar="FILE",
        help="設定ファイルのパス（既定: ./securia.toml → ~/.config/securia/config.toml）",
        **kwargs,
    )
    parser.add_argument(
        "--db", metavar="FILE",
        help="履歴 DB のパス（既定: データディレクトリ内の securia.db）",
        **kwargs,
    )


def build_parser() -> argparse.ArgumentParser:
    ap = argparse.ArgumentParser(
        prog="securia",
        description="Securia — ローカルで完結する脆弱性スキャナ",
    )
    ap.add_argument("--version", action="version", version=f"securia {__version__}")
    _common_options(ap, suppress=False)

    common = argparse.ArgumentParser(add_help=False)
    _common_options(common, suppress=True)

    _sub = ap.add_subparsers(dest="command", required=True)

    def sub_parser(name: str, help_text: str) -> argparse.ArgumentParser:
        return _sub.add_parser(name, help=help_text, parents=[common])

    p_serve = sub_parser("serve", "ダッシュボードを起動する（既定の動作）")
    p_serve.add_argument("--port", type=int, help="待ち受けポート")
    p_serve.add_argument("--path", help="起動時の初期対象フォルダ")
    p_serve.add_argument("--no-browser", action="store_true", help="ブラウザを自動で開かない")

    p_scan = sub_parser("scan", "1回スキャンして結果を出力する")
    p_scan.add_argument("path", help="スキャン対象ディレクトリ")
    p_scan.add_argument("--out", metavar="FILE", help="JSON の出力先（既定: 標準出力）")
    p_scan.add_argument("--no-osv", action="store_true", help="OSV への問い合わせを行わない（完全オフライン）")
    p_scan.add_argument("--no-save", action="store_true", help="履歴 DB に保存しない")
    p_scan.add_argument("--quiet", action="store_true", help="進捗と要約を表示しない")
    p_scan.add_argument(
        "--fail-on", metavar="SEVERITY", choices=[s.lower() for s in SEVERITIES],
        help="この重要度以上の検出があれば終了コード 1 を返す（critical/high/medium/low/info）",
    )

    p_hist = sub_parser("history", "スキャン履歴を表示する")
    p_hist.add_argument("--target", help="対象ディレクトリで絞り込む")
    p_hist.add_argument("--limit", type=int, default=20)

    p_show = sub_parser("show", "保存済みスキャンの詳細を JSON で出力する")
    p_show.add_argument("scan_id", type=int)

    p_sup = sub_parser("suppress", "検出を抑制する（誤検知を消す）")
    p_sup.add_argument("fingerprint")
    p_sup.add_argument("--target", required=True, help="対象ディレクトリ")
    p_sup.add_argument("--reason", default="", help="抑制する理由")

    p_unsup = sub_parser("unsuppress", "抑制を解除する")
    p_unsup.add_argument("fingerprint")
    p_unsup.add_argument("--target", required=True)

    p_sups = sub_parser("suppressions", "抑制の一覧を表示する")
    p_sups.add_argument("--target")

    sub_parser("rules", "設定で参照できるルール ID の一覧を表示する")

    return ap


def main(argv: list[str] | None = None) -> int:
    argv = list(sys.argv[1:] if argv is None else argv)
    # 引数なしなら serve（従来の `python3 run.py` と同じ体験にする）
    if not argv:
        argv = ["serve"]

    ap = build_parser()
    args = ap.parse_args(argv)

    try:
        cfg = Config.load(args.config)
    except ConfigError as e:
        print(f"設定エラー: {e}", file=sys.stderr)
        return EXIT_ERROR

    if args.command == "rules":
        for rule_id in all_rule_ids():
            print(rule_id)
        return EXIT_OK

    store = Store(args.db)
    try:
        match args.command:
            case "serve":
                return _cmd_serve(args, cfg, store)
            case "scan":
                return _cmd_scan(args, cfg, store)
            case "history":
                return _cmd_history(args, store)
            case "show":
                return _cmd_show(args, store)
            case "suppress":
                return _cmd_suppress(args, store)
            case "unsuppress":
                return _cmd_unsuppress(args, store)
            case "suppressions":
                return _cmd_suppressions(args, store)
            case _:
                ap.error(f"未知のコマンド: {args.command}")
                return EXIT_ERROR
    finally:
        store.close()


# ---------------- 各コマンド ----------------
def _cmd_serve(args: argparse.Namespace, cfg: Config, store: Store) -> int:
    from .server import serve  # 起動時のみ読み込む

    serve(
        cfg, store,
        port=args.port,
        open_browser=False if args.no_browser else None,
        initial_path=args.path,
    )
    return EXIT_OK


def _cmd_scan(args: argparse.Namespace, cfg: Config, store: Store) -> int:
    try:
        target = ensure_scannable(args.path, cfg.scan.allowed_roots)
    except PathNotAllowed as e:
        print(f"エラー: {e}", file=sys.stderr)
        return EXIT_ERROR

    osv_client = None if args.no_osv else (OsvClient(cfg.osv, cache=store) if cfg.osv.enabled else None)
    target_key = str(target)
    previous_scan_id = store.latest_scan_id(target_key)
    suppressed = store.suppressed_fingerprints(target_key)

    progress = None if args.quiet else _stderr_progress()

    try:
        result = run_scan(target, cfg, osv_client=osv_client, suppressed=suppressed, progress=progress)
    except ScanCancelled:
        print("\n中断しました。", file=sys.stderr)
        return EXIT_ERROR
    if progress:
        print(file=sys.stderr)  # 進捗行を閉じる

    scan_diff = diffmod.compare(store, previous_scan_id, result)
    payload = result.to_dict()
    payload["diff"] = scan_diff.to_dict()

    if not args.no_save:
        payload["scan_id"] = store.save_scan(result)

    text = json.dumps(payload, ensure_ascii=False, indent=2)
    if args.out:
        Path(args.out).write_text(text + "\n", encoding="utf-8")
        if not args.quiet:
            print(f"結果を書き出しました: {args.out}", file=sys.stderr)
    else:
        print(text)

    if not args.quiet:
        _print_summary(result, scan_diff, file=sys.stderr)

    if args.fail_on:
        threshold = severity_rank(args.fail_on.upper())
        hits = [f for f in result.active_findings if severity_rank(f.severity) >= threshold]
        if hits:
            if not args.quiet:
                print(f"\n{args.fail_on.upper()} 以上の検出が {len(hits)} 件あります。", file=sys.stderr)
            return EXIT_FINDINGS
    return EXIT_OK


def _cmd_history(args: argparse.Namespace, store: Store) -> int:
    scans = store.list_scans(args.target, args.limit)
    if not scans:
        print("履歴はありません。", file=sys.stderr)
        return EXIT_OK
    print(f"{'ID':>5}  {'日時':<26} {'件数':>5} {'CRIT':>5} {'HIGH':>5}  対象")
    for s in scans:
        counts = s["summary"]["severity_counts"]
        print(f"{s['id']:>5}  {s['scanned_at']:<26} {s['summary']['total_findings']:>5} "
              f"{counts.get('CRITICAL', 0):>5} {counts.get('HIGH', 0):>5}  {s['target']}")
    return EXIT_OK


def _cmd_show(args: argparse.Namespace, store: Store) -> int:
    scan = store.get_scan(args.scan_id)
    if scan is None:
        print(f"スキャン {args.scan_id} は見つかりません。", file=sys.stderr)
        return EXIT_ERROR
    payload = {
        **scan,
        "findings": [f.to_dict() for f in store.load_findings(args.scan_id)],
        "components": [c.to_dict() for c in store.load_components(args.scan_id)],
    }
    print(json.dumps(payload, ensure_ascii=False, indent=2))
    return EXIT_OK


def _cmd_suppress(args: argparse.Namespace, store: Store) -> int:
    target = str(Path(args.target).expanduser().resolve())
    store.suppress_raw(target, args.fingerprint, reason=args.reason)
    print(f"抑制しました: {args.fingerprint} ({target})", file=sys.stderr)
    return EXIT_OK


def _cmd_unsuppress(args: argparse.Namespace, store: Store) -> int:
    target = str(Path(args.target).expanduser().resolve())
    if store.unsuppress(target, args.fingerprint):
        print(f"抑制を解除しました: {args.fingerprint}", file=sys.stderr)
        return EXIT_OK
    print("該当する抑制がありません。", file=sys.stderr)
    return EXIT_ERROR


def _cmd_suppressions(args: argparse.Namespace, store: Store) -> int:
    target = str(Path(args.target).expanduser().resolve()) if args.target else None
    rows = store.list_suppressions(target)
    if not rows:
        print("抑制はありません。", file=sys.stderr)
        return EXIT_OK
    for r in rows:
        reason = f"  # {r['reason']}" if r["reason"] else ""
        print(f"{r['fingerprint']}  {r['rule_id'] or '-':<28} {r['file'] or '-'}{reason}")
    return EXIT_OK


# ---------------- 表示ヘルパ ----------------
def _stderr_progress():
    """進捗表示。端末なら1行を上書きし、リダイレクト先ではフェーズの変わり目だけ出す。

    キャリッジリターンでの上書きはログファイルや CI の出力では読めない
    ゴミになるので、TTY かどうかで挙動を変える。
    """
    is_tty = sys.stderr.isatty()
    state = {"last": "", "phase": ""}

    def progress(phase: str, current: int, total: int) -> None:
        if not is_tty:
            if phase != state["phase"]:
                state["phase"] = phase
                print(f"  {phase}…", file=sys.stderr, flush=True)
            return

        if total > 0:
            line = f"  {phase}… {current}/{total}"
        elif current > 0:
            line = f"  {phase}… {current}"
        else:
            line = f"  {phase}…"
        if line != state["last"]:
            padding = max(0, len(state["last"]) - len(line))
            print("\r" + line + " " * padding, end="", file=sys.stderr, flush=True)
            state["last"] = line

    return progress


def _print_summary(result: ScanResult, scan_diff: diffmod.ScanDiff, file) -> None:
    s = result.summary()
    counts = s["severity_counts"]
    print(f"\n対象: {result.target}", file=file)
    print(f"  {s['total_files']} ファイル / {s['total_components']} コンポーネント / {result.elapsed_sec} 秒",
          file=file)
    if result.osv_status == STATUS_OFFLINE:
        print("  ⚠ OSV に接続できず、依存関係の CVE 照合はスキップしました。", file=file)
    elif result.osv_status == STATUS_DISABLED:
        print("  ⓘ OSV 照合は無効です。", file=file)
    print("  検出: " + "  ".join(f"{sev}={counts.get(sev, 0)}" for sev in SEVERITIES), file=file)
    if s["suppressed_findings"]:
        print(f"  抑制済み: {s['suppressed_findings']} 件", file=file)
    if scan_diff.has_baseline:
        print(f"  前回比: 新規 {scan_diff.new_count} / 修正済み {scan_diff.fixed_count} / "
              f"継続 {scan_diff.existing_count}", file=file)


if __name__ == "__main__":
    sys.exit(main())
