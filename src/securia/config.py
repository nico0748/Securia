"""securia.toml の読み込み。

設定が無くても既定値だけで完全に動く。設定ファイルは「うるさいルールを黙らせる」
「スキャンして良い場所を広げる」ための調整レイヤーとして位置づける。
"""
from __future__ import annotations

import tomllib
from dataclasses import dataclass, field
from fnmatch import fnmatch
from pathlib import Path
from typing import Any

from .models import SEVERITY_ORDER
from .paths import config_search_paths

DEFAULT_SKIP_DIRS = frozenset({
    ".git", ".hg", ".svn", "node_modules", "bower_components", "vendor",
    "dist", "build", "out", ".next", ".nuxt", "target", ".venv", "venv",
    "env", "__pycache__", ".mypy_cache", ".pytest_cache", ".ruff_cache",
    ".gradle", ".idea", ".vscode", "coverage", ".terraform", ".cache",
    "site-packages", ".tox", ".eggs",
})


class ConfigError(Exception):
    """設定ファイルの内容が不正。"""


@dataclass
class ScanConfig:
    allowed_roots: list[str] = field(default_factory=lambda: [str(Path.home())])
    skip_dirs: frozenset[str] = DEFAULT_SKIP_DIRS
    skip_globs: list[str] = field(default_factory=list)
    max_file_bytes: int = 2 * 1024 * 1024
    follow_symlinks: bool = False


@dataclass
class RulesConfig:
    disabled: list[str] = field(default_factory=list)
    severity: dict[str, str] = field(default_factory=dict)

    def is_disabled(self, rule_id: str) -> bool:
        return any(fnmatch(rule_id, pat) for pat in self.disabled)

    def severity_for(self, rule_id: str, default: str) -> str:
        """設定による重要度の上書き。完全一致を優先し、無ければ glob。"""
        if rule_id in self.severity:
            return self.severity[rule_id]
        for pat, sev in self.severity.items():
            if fnmatch(rule_id, pat):
                return sev
        return default


@dataclass
class OsvConfig:
    enabled: bool = True
    timeout: float = 20.0
    max_workers: int = 8
    cache_ttl_days: int = 7


@dataclass
class ServerConfig:
    port: int = 8787
    open_browser: bool = True


@dataclass
class Config:
    scan: ScanConfig = field(default_factory=ScanConfig)
    rules: RulesConfig = field(default_factory=RulesConfig)
    osv: OsvConfig = field(default_factory=OsvConfig)
    server: ServerConfig = field(default_factory=ServerConfig)
    source: Path | None = None

    @classmethod
    def load(cls, explicit: str | Path | None = None) -> Config:
        """設定を読む。explicit が与えられればそれだけを見る（無ければエラー）。"""
        if explicit is not None:
            p = Path(explicit).expanduser()
            if not p.is_file():
                raise ConfigError(f"設定ファイルが見つかりません: {p}")
            return cls.from_file(p)

        for p in config_search_paths():
            if p.is_file():
                return cls.from_file(p)
        return cls()

    @classmethod
    def from_file(cls, path: Path) -> Config:
        try:
            with open(path, "rb") as f:
                raw = tomllib.load(f)
        except tomllib.TOMLDecodeError as e:
            raise ConfigError(f"{path}: TOML として読めません: {e}") from e
        except OSError as e:
            raise ConfigError(f"{path}: 読み込めません: {e}") from e
        cfg = cls.from_dict(raw, origin=str(path))
        cfg.source = path
        return cfg

    @classmethod
    def from_dict(cls, raw: dict[str, Any], origin: str = "<dict>") -> Config:
        cfg = cls()
        scan = _table(raw, "scan", origin)
        if "allowed_roots" in scan:
            roots = _str_list(scan["allowed_roots"], f"{origin}: [scan] allowed_roots")
            cfg.scan.allowed_roots = roots
        if "skip_dirs" in scan:
            extra = _str_list(scan["skip_dirs"], f"{origin}: [scan] skip_dirs")
            cfg.scan.skip_dirs = DEFAULT_SKIP_DIRS | frozenset(extra)
        if "skip_globs" in scan:
            cfg.scan.skip_globs = _str_list(scan["skip_globs"], f"{origin}: [scan] skip_globs")
        if "max_file_bytes" in scan:
            cfg.scan.max_file_bytes = _positive_int(scan["max_file_bytes"], f"{origin}: [scan] max_file_bytes")
        if "follow_symlinks" in scan:
            cfg.scan.follow_symlinks = _bool(scan["follow_symlinks"], f"{origin}: [scan] follow_symlinks")

        rules = _table(raw, "rules", origin)
        if "disabled" in rules:
            cfg.rules.disabled = _str_list(rules["disabled"], f"{origin}: [rules] disabled")
        sev = rules.get("severity", {})
        if sev:
            if not isinstance(sev, dict):
                raise ConfigError(f"{origin}: [rules.severity] はテーブルである必要があります")
            out: dict[str, str] = {}
            for rule_id, value in sev.items():
                if not isinstance(value, str) or value.upper() not in SEVERITY_ORDER:
                    raise ConfigError(
                        f"{origin}: [rules.severity] {rule_id} の値が不正です: {value!r}\n"
                        f"使えるのは {', '.join(SEVERITY_ORDER)} です。"
                    )
                out[rule_id] = value.upper()
            cfg.rules.severity = out

        osv = _table(raw, "osv", origin)
        if "enabled" in osv:
            cfg.osv.enabled = _bool(osv["enabled"], f"{origin}: [osv] enabled")
        if "timeout" in osv:
            cfg.osv.timeout = _positive_number(osv["timeout"], f"{origin}: [osv] timeout")
        if "max_workers" in osv:
            cfg.osv.max_workers = _positive_int(osv["max_workers"], f"{origin}: [osv] max_workers")
        if "cache_ttl_days" in osv:
            cfg.osv.cache_ttl_days = _positive_int(osv["cache_ttl_days"], f"{origin}: [osv] cache_ttl_days")

        server = _table(raw, "server", origin)
        if "port" in server:
            port = _positive_int(server["port"], f"{origin}: [server] port")
            if port > 65535:
                raise ConfigError(f"{origin}: [server] port が範囲外です: {port}")
            cfg.server.port = port
        if "open_browser" in server:
            cfg.server.open_browser = _bool(server["open_browser"], f"{origin}: [server] open_browser")

        return cfg


def _table(raw: dict[str, Any], key: str, origin: str) -> dict[str, Any]:
    value = raw.get(key, {})
    if not isinstance(value, dict):
        raise ConfigError(f"{origin}: [{key}] はテーブルである必要があります")
    return value


def _str_list(value: Any, where: str) -> list[str]:
    if not isinstance(value, list) or not all(isinstance(v, str) for v in value):
        raise ConfigError(f"{where} は文字列の配列である必要があります")
    return list(value)


def _bool(value: Any, where: str) -> bool:
    if not isinstance(value, bool):
        raise ConfigError(f"{where} は true/false である必要があります")
    return value


def _positive_int(value: Any, where: str) -> int:
    if not isinstance(value, int) or isinstance(value, bool) or value <= 0:
        raise ConfigError(f"{where} は正の整数である必要があります")
    return value


def _positive_number(value: Any, where: str) -> float:
    if isinstance(value, bool) or not isinstance(value, (int, float)) or value <= 0:
        raise ConfigError(f"{where} は正の数である必要があります")
    return float(value)
