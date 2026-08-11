"""スキャン用の下位モジュール群。

ここには「テキストを受け取って Finding / Component を返す」純粋な処理だけを置く。
オーケストレーション（走査順・OSV 照合・集計）は securia.engine が持つ。
分けているのは、この層をネットワーク無しでテストできるようにするため。
"""
from __future__ import annotations

from . import config_scan, cvss, dependency, static_code, walker

__all__ = ["config_scan", "cvss", "dependency", "static_code", "walker"]


def all_rule_ids() -> list[str]:
    """設定で参照できる静的/設定診断のルール ID 一覧。

    依存関係の検出は OSV の脆弱性 ID がそのまま rule_id になるため含まない。
    """
    return sorted(set(static_code.ALL_RULE_IDS) | set(config_scan.ALL_RULE_IDS))
