"""securia.toml の読み込みと検証。"""
from __future__ import annotations

from pathlib import Path

import pytest

from securia.config import DEFAULT_SKIP_DIRS, Config, ConfigError, RulesConfig


def load(tmp_path: Path, toml: str) -> Config:
    p = tmp_path / "securia.toml"
    p.write_text(toml, encoding="utf-8")
    return Config.from_file(p)


def test_defaults_without_file() -> None:
    cfg = Config()
    assert cfg.osv.enabled is True
    assert cfg.server.port == 8787
    assert cfg.scan.allowed_roots == [str(Path.home())]
    assert cfg.rules.disabled == []


def test_full_config(tmp_path: Path) -> None:
    cfg = load(tmp_path, """
[scan]
allowed_roots = ["/work", "~/src"]
skip_dirs = ["fixtures"]
skip_globs = ["*.generated.py"]
max_file_bytes = 1024
follow_symlinks = true

[rules]
disabled = ["code.http_url", "secret.*"]

[rules.severity]
"code.weak_hash" = "info"

[osv]
enabled = false
timeout = 5.5
max_workers = 2
cache_ttl_days = 30

[server]
port = 9000
open_browser = false
""")
    assert cfg.scan.allowed_roots == ["/work", "~/src"]
    assert "fixtures" in cfg.scan.skip_dirs
    assert "node_modules" in cfg.scan.skip_dirs      # 既定は保たれる
    assert cfg.scan.skip_globs == ["*.generated.py"]
    assert cfg.scan.max_file_bytes == 1024
    assert cfg.scan.follow_symlinks is True
    assert cfg.rules.disabled == ["code.http_url", "secret.*"]
    assert cfg.rules.severity == {"code.weak_hash": "INFO"}
    assert cfg.osv.enabled is False
    assert cfg.osv.timeout == 5.5
    assert cfg.server.port == 9000
    assert cfg.source == tmp_path / "securia.toml"


def test_skip_dirs_extends_rather_than_replaces(tmp_path: Path) -> None:
    cfg = load(tmp_path, '[scan]\nskip_dirs = ["mine"]\n')
    assert cfg.scan.skip_dirs == DEFAULT_SKIP_DIRS | {"mine"}


@pytest.mark.parametrize(
    "toml",
    [
        '[scan]\nallowed_roots = "not-a-list"\n',
        "[scan]\nallowed_roots = [1, 2]\n",
        "[scan]\nmax_file_bytes = 0\n",
        "[scan]\nmax_file_bytes = -5\n",
        '[scan]\nfollow_symlinks = "yes"\n',
        '[rules.severity]\n"code.x" = "SEVERE"\n',
        "[osv]\ntimeout = 0\n",
        "[osv]\nmax_workers = -1\n",
        "[server]\nport = 99999\n",
        "[server]\nport = 0\n",
        "scan = 5\n",
    ],
)
def test_invalid_values_are_rejected(tmp_path: Path, toml: str) -> None:
    with pytest.raises(ConfigError):
        load(tmp_path, toml)


def test_malformed_toml(tmp_path: Path) -> None:
    with pytest.raises(ConfigError, match="TOML"):
        load(tmp_path, "[scan\nbroken")


def test_missing_explicit_file(tmp_path: Path) -> None:
    with pytest.raises(ConfigError, match="見つかりません"):
        Config.load(tmp_path / "nope.toml")


def test_error_message_names_the_setting(tmp_path: Path) -> None:
    with pytest.raises(ConfigError, match=r"\[osv\] max_workers"):
        load(tmp_path, "[osv]\nmax_workers = 0\n")


# ---------------- ルール判定 ----------------
def test_rule_disabled_exact_and_glob() -> None:
    rules = RulesConfig(disabled=["code.os_system", "secret.*"])
    assert rules.is_disabled("code.os_system")
    assert rules.is_disabled("secret.aws_access_key")
    assert not rules.is_disabled("code.py_eval")


def test_severity_override_precedence() -> None:
    """完全一致は glob より優先する。"""
    rules = RulesConfig(severity={"code.*": "INFO", "code.os_system": "CRITICAL"})
    assert rules.severity_for("code.os_system", "HIGH") == "CRITICAL"
    assert rules.severity_for("code.py_eval", "HIGH") == "INFO"
    assert rules.severity_for("secret.jwt", "MEDIUM") == "MEDIUM"
