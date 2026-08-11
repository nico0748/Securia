"""SQLite による永続化。

保持するもの: スキャン履歴、検出結果、SBOM、抑制、OSV レコードのキャッシュ。

保持しないもの: 一致した行の生テキスト。秘密情報の検出結果をそのまま
書き込むと DB 自体が秘密情報の置き場になってしまうため、fingerprint の
材料としてハッシュ化した後は捨てる。UI で本文が要るときはファイルから
その場で読む（walker.read_snippet）。
"""
from __future__ import annotations

import json
import sqlite3
import threading
import time
from pathlib import Path
from typing import Any

from .engine import ScanResult
from .models import Component, Finding
from .paths import data_dir

SCHEMA_VERSION = 1

_SCHEMA = """
CREATE TABLE IF NOT EXISTS meta (
    key   TEXT PRIMARY KEY,
    value TEXT NOT NULL
);

CREATE TABLE IF NOT EXISTS scans (
    id           INTEGER PRIMARY KEY AUTOINCREMENT,
    target       TEXT    NOT NULL,
    scanned_at   TEXT    NOT NULL,
    elapsed_sec  REAL    NOT NULL,
    osv_status   TEXT    NOT NULL,
    total_files  INTEGER NOT NULL,
    summary_json TEXT    NOT NULL
);
CREATE INDEX IF NOT EXISTS idx_scans_target ON scans(target, id DESC);

CREATE TABLE IF NOT EXISTS findings (
    scan_id        INTEGER NOT NULL REFERENCES scans(id) ON DELETE CASCADE,
    fingerprint    TEXT    NOT NULL,
    occurrence     INTEGER NOT NULL,
    category       TEXT    NOT NULL,
    severity       TEXT    NOT NULL,
    title          TEXT    NOT NULL,
    rule_id        TEXT    NOT NULL,
    description    TEXT    NOT NULL DEFAULT '',
    recommendation TEXT    NOT NULL DEFAULT '',
    file           TEXT    NOT NULL DEFAULT '',
    line           INTEGER NOT NULL DEFAULT 0,
    package        TEXT    NOT NULL DEFAULT '',
    version        TEXT    NOT NULL DEFAULT '',
    ecosystem      TEXT    NOT NULL DEFAULT '',
    refs_json      TEXT    NOT NULL DEFAULT '[]',
    fixed_version  TEXT    NOT NULL DEFAULT '',
    status         TEXT    NOT NULL DEFAULT 'existing',
    suppressed     INTEGER NOT NULL DEFAULT 0,
    PRIMARY KEY (scan_id, fingerprint, occurrence)
);
CREATE INDEX IF NOT EXISTS idx_findings_scan ON findings(scan_id);

CREATE TABLE IF NOT EXISTS components (
    scan_id      INTEGER NOT NULL REFERENCES scans(id) ON DELETE CASCADE,
    name         TEXT    NOT NULL,
    version      TEXT    NOT NULL,
    ecosystem    TEXT    NOT NULL,
    file         TEXT    NOT NULL DEFAULT '',
    scope        TEXT    NOT NULL DEFAULT 'runtime',
    vuln_count   INTEGER NOT NULL DEFAULT 0,
    max_severity TEXT    NOT NULL DEFAULT 'INFO',
    PRIMARY KEY (scan_id, ecosystem, name, version)
);

CREATE TABLE IF NOT EXISTS suppressions (
    target      TEXT NOT NULL,
    fingerprint TEXT NOT NULL,
    rule_id     TEXT NOT NULL DEFAULT '',
    file        TEXT NOT NULL DEFAULT '',
    title       TEXT NOT NULL DEFAULT '',
    reason      TEXT NOT NULL DEFAULT '',
    created_at  INTEGER NOT NULL,
    PRIMARY KEY (target, fingerprint)
);

CREATE TABLE IF NOT EXISTS osv_cache (
    vuln_id    TEXT PRIMARY KEY,
    data_json  TEXT    NOT NULL,
    fetched_at INTEGER NOT NULL
);
"""


class Store:
    """スキャン履歴・抑制・OSV キャッシュの保存先。

    サーバは複数スレッドから触るので、単一接続をロックで直列化する。
    このアプリの書き込み量では十分で、接続プールを持つ必要はない。
    """

    def __init__(self, path: str | Path | None = None) -> None:
        self.path = Path(path) if path is not None else data_dir() / "securia.db"
        if str(self.path) != ":memory:":
            self.path.parent.mkdir(parents=True, exist_ok=True)
        self._lock = threading.RLock()
        self._conn = sqlite3.connect(str(self.path), check_same_thread=False)
        self._conn.row_factory = sqlite3.Row
        self._conn.execute("PRAGMA foreign_keys = ON")
        if str(self.path) != ":memory:":
            self._conn.execute("PRAGMA journal_mode = WAL")
        self._migrate()

    # ---------------- ライフサイクル ----------------
    def _migrate(self) -> None:
        with self._lock, self._conn:
            self._conn.executescript(_SCHEMA)
            self._conn.execute(
                "INSERT INTO meta(key, value) VALUES('schema_version', ?) "
                "ON CONFLICT(key) DO UPDATE SET value=excluded.value",
                (str(SCHEMA_VERSION),),
            )

    def close(self) -> None:
        with self._lock:
            self._conn.close()

    def __enter__(self) -> Store:
        return self

    def __exit__(self, *exc: object) -> None:
        self.close()

    # ---------------- スキャン ----------------
    def save_scan(self, result: ScanResult) -> int:
        with self._lock, self._conn:
            cur = self._conn.execute(
                "INSERT INTO scans(target, scanned_at, elapsed_sec, osv_status, total_files, summary_json) "
                "VALUES(?,?,?,?,?,?)",
                (
                    result.target,
                    result.scanned_at,
                    result.elapsed_sec,
                    result.osv_status,
                    result.total_files,
                    json.dumps(result.summary(), ensure_ascii=False),
                ),
            )
            scan_id = int(cur.lastrowid)

            self._conn.executemany(
                "INSERT INTO findings(scan_id, fingerprint, occurrence, category, severity, title, rule_id,"
                " description, recommendation, file, line, package, version, ecosystem, refs_json,"
                " fixed_version, status, suppressed) VALUES(?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?)",
                [
                    (
                        scan_id, f.fingerprint, f.occurrence, f.category, f.severity, f.title, f.rule_id,
                        f.description, f.recommendation, f.file, f.line, f.package, f.version, f.ecosystem,
                        json.dumps(f.references, ensure_ascii=False), f.fixed_version, f.status,
                        1 if f.suppressed else 0,
                    )
                    for f in result.findings
                ],
            )
            self._conn.executemany(
                "INSERT OR REPLACE INTO components(scan_id, name, version, ecosystem, file, scope,"
                " vuln_count, max_severity) VALUES(?,?,?,?,?,?,?,?)",
                [
                    (scan_id, c.name, c.version, c.ecosystem, c.file, c.scope, c.vuln_count, c.max_severity)
                    for c in result.components
                ],
            )
        return scan_id

    def list_scans(self, target: str | None = None, limit: int = 50) -> list[dict]:
        sql = "SELECT * FROM scans"
        args: list[Any] = []
        if target:
            sql += " WHERE target = ?"
            args.append(target)
        sql += " ORDER BY id DESC LIMIT ?"
        args.append(limit)
        with self._lock:
            rows = self._conn.execute(sql, args).fetchall()
        return [self._scan_row(r) for r in rows]

    def list_targets(self) -> list[dict]:
        """スキャンしたことのある対象と、その最新スキャンの概要。"""
        with self._lock:
            rows = self._conn.execute(
                "SELECT target, COUNT(*) AS scan_count, MAX(id) AS last_scan_id FROM scans GROUP BY target"
            ).fetchall()
        out = []
        for r in rows:
            last = self.get_scan(int(r["last_scan_id"]))
            out.append({
                "target": r["target"],
                "scan_count": int(r["scan_count"]),
                "last_scan": last,
            })
        out.sort(key=lambda t: t["last_scan"]["scanned_at"] if t["last_scan"] else "", reverse=True)
        return out

    def get_scan(self, scan_id: int) -> dict | None:
        with self._lock:
            row = self._conn.execute("SELECT * FROM scans WHERE id = ?", (scan_id,)).fetchone()
        return self._scan_row(row) if row else None

    def latest_scan_id(self, target: str) -> int | None:
        with self._lock:
            row = self._conn.execute(
                "SELECT id FROM scans WHERE target = ? ORDER BY id DESC LIMIT 1", (target,)
            ).fetchone()
        return int(row["id"]) if row else None

    def load_findings(self, scan_id: int) -> list[Finding]:
        with self._lock:
            rows = self._conn.execute(
                "SELECT * FROM findings WHERE scan_id = ? ORDER BY rowid", (scan_id,)
            ).fetchall()
        return [self._finding_row(r) for r in rows]

    def load_components(self, scan_id: int) -> list[Component]:
        with self._lock:
            rows = self._conn.execute(
                "SELECT * FROM components WHERE scan_id = ?", (scan_id,)
            ).fetchall()
        return [
            Component(
                name=r["name"], version=r["version"], ecosystem=r["ecosystem"], file=r["file"],
                scope=r["scope"], vuln_count=r["vuln_count"], max_severity=r["max_severity"],
            )
            for r in rows
        ]

    def fingerprints_of(self, scan_id: int) -> set[str]:
        with self._lock:
            rows = self._conn.execute(
                "SELECT DISTINCT fingerprint FROM findings WHERE scan_id = ?", (scan_id,)
            ).fetchall()
        return {r["fingerprint"] for r in rows}

    def delete_scan(self, scan_id: int) -> bool:
        with self._lock, self._conn:
            cur = self._conn.execute("DELETE FROM scans WHERE id = ?", (scan_id,))
            self._conn.execute("DELETE FROM findings WHERE scan_id = ?", (scan_id,))
            self._conn.execute("DELETE FROM components WHERE scan_id = ?", (scan_id,))
        return cur.rowcount > 0

    def prune(self, target: str, keep: int) -> int:
        """1ターゲットあたり最新 keep 件だけ残す。戻り値は削除件数。"""
        with self._lock:
            rows = self._conn.execute(
                "SELECT id FROM scans WHERE target = ? ORDER BY id DESC LIMIT -1 OFFSET ?",
                (target, keep),
            ).fetchall()
        for r in rows:
            self.delete_scan(int(r["id"]))
        return len(rows)

    # ---------------- 抑制 ----------------
    def suppress(self, target: str, finding: Finding, reason: str = "") -> None:
        with self._lock, self._conn:
            self._conn.execute(
                "INSERT INTO suppressions(target, fingerprint, rule_id, file, title, reason, created_at) "
                "VALUES(?,?,?,?,?,?,?) ON CONFLICT(target, fingerprint) DO UPDATE SET reason=excluded.reason",
                (target, finding.fingerprint, finding.rule_id, finding.file, finding.title,
                 reason, int(time.time())),
            )

    def suppress_raw(self, target: str, fingerprint: str, reason: str = "", *,
                     rule_id: str = "", file: str = "", title: str = "") -> None:
        with self._lock, self._conn:
            self._conn.execute(
                "INSERT INTO suppressions(target, fingerprint, rule_id, file, title, reason, created_at) "
                "VALUES(?,?,?,?,?,?,?) ON CONFLICT(target, fingerprint) DO UPDATE SET reason=excluded.reason",
                (target, fingerprint, rule_id, file, title, reason, int(time.time())),
            )

    def unsuppress(self, target: str, fingerprint: str) -> bool:
        with self._lock, self._conn:
            cur = self._conn.execute(
                "DELETE FROM suppressions WHERE target = ? AND fingerprint = ?", (target, fingerprint)
            )
        return cur.rowcount > 0

    def suppressed_fingerprints(self, target: str) -> set[str]:
        with self._lock:
            rows = self._conn.execute(
                "SELECT fingerprint FROM suppressions WHERE target = ?", (target,)
            ).fetchall()
        return {r["fingerprint"] for r in rows}

    def list_suppressions(self, target: str | None = None) -> list[dict]:
        sql = "SELECT * FROM suppressions"
        args: list[Any] = []
        if target:
            sql += " WHERE target = ?"
            args.append(target)
        sql += " ORDER BY created_at DESC"
        with self._lock:
            rows = self._conn.execute(sql, args).fetchall()
        return [dict(r) for r in rows]

    # ---------------- OSV キャッシュ（VulnCache プロトコル）----------------
    def get_vuln(self, vuln_id: str, ttl_days: int) -> dict | None:
        cutoff = int(time.time()) - ttl_days * 86400
        with self._lock:
            row = self._conn.execute(
                "SELECT data_json FROM osv_cache WHERE vuln_id = ? AND fetched_at >= ?",
                (vuln_id, cutoff),
            ).fetchone()
        if row is None:
            return None
        try:
            return json.loads(row["data_json"])
        except ValueError:
            return None

    def put_vuln(self, vuln_id: str, data: dict) -> None:
        with self._lock, self._conn:
            self._conn.execute(
                "INSERT INTO osv_cache(vuln_id, data_json, fetched_at) VALUES(?,?,?) "
                "ON CONFLICT(vuln_id) DO UPDATE SET data_json=excluded.data_json, fetched_at=excluded.fetched_at",
                (vuln_id, json.dumps(data, ensure_ascii=False), int(time.time())),
            )

    def clear_vuln_cache(self) -> int:
        with self._lock, self._conn:
            cur = self._conn.execute("DELETE FROM osv_cache")
        return cur.rowcount

    # ---------------- 行 → オブジェクト ----------------
    @staticmethod
    def _scan_row(row: sqlite3.Row) -> dict:
        return {
            "id": int(row["id"]),
            "target": row["target"],
            "scanned_at": row["scanned_at"],
            "elapsed_sec": row["elapsed_sec"],
            "osv_status": row["osv_status"],
            "total_files": int(row["total_files"]),
            "summary": json.loads(row["summary_json"]),
        }

    @staticmethod
    def _finding_row(row: sqlite3.Row) -> Finding:
        f = Finding(
            category=row["category"], severity=row["severity"], title=row["title"],
            rule_id=row["rule_id"], description=row["description"],
            recommendation=row["recommendation"], file=row["file"], line=int(row["line"]),
            package=row["package"], version=row["version"], ecosystem=row["ecosystem"],
            references=json.loads(row["refs_json"]), fixed_version=row["fixed_version"],
        )
        f.fingerprint = row["fingerprint"]
        f.occurrence = int(row["occurrence"])
        f.status = row["status"]
        f.suppressed = bool(row["suppressed"])
        return f
