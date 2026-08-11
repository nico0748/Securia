"""非同期スキャンジョブと進捗配信。

以前はリクエストハンドラの中で同期的にスキャンしていたため、大きな
リポジトリではブラウザが無反応になり、中断する手段も無かった。
ここではワーカースレッドで走らせ、進捗をキュー経由で購読者へ流す。
"""
from __future__ import annotations

import queue
import secrets
import threading
import time
from collections.abc import Iterator
from dataclasses import dataclass, field
from pathlib import Path

from . import diff as diffmod
from .config import Config
from .engine import ScanResult, run_scan
from .osv import OsvClient
from .scan.walker import ScanCancelled
from .store import Store

STATE_RUNNING = "running"
STATE_DONE = "done"
STATE_ERROR = "error"
STATE_CANCELLED = "cancelled"

MAX_CONCURRENT = 4
KEEP_FINISHED = 20

_SENTINEL = object()


@dataclass
class Job:
    id: str
    target: str
    state: str = STATE_RUNNING
    phase: str = "準備中"
    current: int = 0
    total: int = 0
    started_at: float = field(default_factory=time.time)
    finished_at: float | None = None
    scan_id: int | None = None
    payload: dict | None = None      # 完了時のレスポンス本体
    error: str | None = None
    cancel: threading.Event = field(default_factory=threading.Event)

    def snapshot(self) -> dict:
        return {
            "type": "state",
            "job_id": self.id,
            "target": self.target,
            "state": self.state,
            "phase": self.phase,
            "current": self.current,
            "total": self.total,
            "elapsed_sec": round((self.finished_at or time.time()) - self.started_at, 1),
            "scan_id": self.scan_id,
            "error": self.error,
        }


class JobBusy(Exception):
    """同時実行数の上限に達している。"""


class JobManager:
    """スキャンジョブの起動・監視・中断。"""

    def __init__(self, store: Store, cfg: Config) -> None:
        self.store = store
        self.cfg = cfg
        self._lock = threading.RLock()
        self._jobs: dict[str, Job] = {}
        self._order: list[str] = []
        self._subscribers: dict[str, list[queue.Queue]] = {}

    # ---------------- 起動 ----------------
    def start(self, target: Path, osv_client: OsvClient | None) -> Job:
        with self._lock:
            running = sum(1 for j in self._jobs.values() if j.state == STATE_RUNNING)
            if running >= MAX_CONCURRENT:
                raise JobBusy(f"同時に実行できるスキャンは {MAX_CONCURRENT} 件までです。")
            job = Job(id=secrets.token_urlsafe(9), target=str(target))
            self._jobs[job.id] = job
            self._order.append(job.id)
            self._subscribers[job.id] = []
            self._evict_locked()

        thread = threading.Thread(
            target=self._run, args=(job, target, osv_client), name=f"securia-scan-{job.id}", daemon=True
        )
        thread.start()
        return job

    def _evict_locked(self) -> None:
        """終了済みジョブが溜まりすぎないよう古いものから捨てる。"""
        finished = [jid for jid in self._order if self._jobs[jid].state != STATE_RUNNING]
        for jid in finished[:-KEEP_FINISHED] if len(finished) > KEEP_FINISHED else []:
            self._jobs.pop(jid, None)
            self._subscribers.pop(jid, None)
            self._order.remove(jid)

    # ---------------- 実行本体 ----------------
    def _run(self, job: Job, target: Path, osv_client: OsvClient | None) -> None:
        def progress(phase: str, current: int, total: int) -> None:
            job.phase = phase
            job.current = current
            job.total = total
            self._publish(job.id, {
                "type": "progress", "phase": phase, "current": current, "total": total,
            })

        try:
            target_key = str(target)
            previous_scan_id = self.store.latest_scan_id(target_key)
            suppressed = self.store.suppressed_fingerprints(target_key)

            result: ScanResult = run_scan(
                target, self.cfg,
                osv_client=osv_client,
                suppressed=suppressed,
                progress=progress,
                cancel=job.cancel,
            )

            progress("結果を保存中", 1, 1)
            scan_diff = diffmod.compare(self.store, previous_scan_id, result)
            scan_id = self.store.save_scan(result)

            payload = result.to_dict()
            payload["scan_id"] = scan_id
            payload["diff"] = scan_diff.to_dict()
            payload["suppressed_fingerprints"] = sorted(suppressed)

            with self._lock:
                job.scan_id = scan_id
                job.payload = payload
                job.state = STATE_DONE
                job.finished_at = time.time()
            self._publish(job.id, {"type": "done", "job_id": job.id, "scan_id": scan_id})

        except ScanCancelled:
            with self._lock:
                job.state = STATE_CANCELLED
                job.finished_at = time.time()
            self._publish(job.id, {"type": "cancelled", "job_id": job.id})
        except Exception as e:  # noqa: BLE001 — 何が起きてもジョブとして記録する
            with self._lock:
                job.state = STATE_ERROR
                job.error = f"{type(e).__name__}: {e}"
                job.finished_at = time.time()
            self._publish(job.id, {"type": "error", "job_id": job.id, "message": job.error})
        finally:
            self._close_subscribers(job.id)

    # ---------------- 参照・操作 ----------------
    def get(self, job_id: str) -> Job | None:
        with self._lock:
            return self._jobs.get(job_id)

    def cancel(self, job_id: str) -> bool:
        with self._lock:
            job = self._jobs.get(job_id)
            if job is None or job.state != STATE_RUNNING:
                return False
            job.cancel.set()
        return True

    def list_jobs(self) -> list[dict]:
        with self._lock:
            return [self._jobs[jid].snapshot() for jid in reversed(self._order) if jid in self._jobs]

    # ---------------- 進捗の購読（SSE 用）----------------
    def subscribe(self, job_id: str) -> Iterator[dict]:
        """ジョブの進捗イベントを順に返す。終了イベントを出したら止まる。

        購読開始時点の状態を最初に1つ返すので、ジョブが既に終わっていても
        購読側が待ちっぱなしにならない。
        """
        q: queue.Queue = queue.Queue()
        with self._lock:
            job = self._jobs.get(job_id)
            if job is None:
                return
            snapshot = job.snapshot()
            already_finished = job.state != STATE_RUNNING
            if not already_finished:
                self._subscribers.setdefault(job_id, []).append(q)

        yield snapshot
        if already_finished:
            return

        while True:
            item = q.get()
            if item is _SENTINEL:
                return
            yield item

    def _publish(self, job_id: str, event: dict) -> None:
        with self._lock:
            subs = list(self._subscribers.get(job_id, []))
        for q in subs:
            q.put(event)

    def _close_subscribers(self, job_id: str) -> None:
        with self._lock:
            subs = self._subscribers.pop(job_id, [])
            self._subscribers[job_id] = []
        for q in subs:
            q.put(_SENTINEL)
