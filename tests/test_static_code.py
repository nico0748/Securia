"""静的コード解析ルール。"""
from __future__ import annotations

import pytest

from securia.config import RulesConfig
from securia.scan import static_code as sc


def scan(entry_factory, relpath: str, content: str, rules: RulesConfig | None = None):
    entry = entry_factory(relpath, content)
    return sc.scan_file(entry, content, rules or RulesConfig())


def rule_ids(findings) -> set[str]:
    return {f.rule_id for f in findings}


# ---------------- 秘密情報 ----------------
@pytest.mark.parametrize(
    ("content", "rule"),
    [
        ('key = "AKIAIOSFODNN7EXAMPLE"', "secret.aws_access_key"),
        ("-----BEGIN RSA PRIVATE KEY-----", "secret.private_key"),
        ("-----BEGIN OPENSSH PRIVATE KEY-----", "secret.private_key"),
        (f'tok = "ghp_{"a" * 36}"', "secret.github_token"),
        ('t = "xoxb-1234567890-abcdefghijk"', "secret.slack_token"),
        (f'k = "AIza{"B" * 35}"', "secret.google_api_key"),
        (f'k = "sk_live_{"c" * 24}"', "secret.stripe_key"),
        ('u = "https://hooks.slack.com/services/T00/B00/XXXXXXXX"', "secret.slack_webhook"),
    ],
)
def test_secret_patterns_detected(entry_factory, content: str, rule: str) -> None:
    assert rule in rule_ids(scan(entry_factory, "app.py", content))


def test_jwt_detected(entry_factory) -> None:
    jwt = "eyJhbGciOiJIUzI1NiJ9.eyJzdWIiOiIxMjM0NTY3ODkwIn0.SflKxwRJSMeKKF2QT4fwpMeJf36"
    assert "secret.jwt" in rule_ids(scan(entry_factory, "app.js", f'const t = "{jwt}";'))


def test_secrets_are_reported_even_inside_comments(entry_factory) -> None:
    """コメントに書かれていても漏れているものは漏れている。"""
    found = scan(entry_factory, "app.py", '# old key was AKIAIOSFODNN7EXAMPLE')
    assert "secret.aws_access_key" in rule_ids(found)


# ---------------- 代入型シークレット ----------------
def test_assignment_secret_detected(entry_factory) -> None:
    found = scan(entry_factory, "app.py", 'password = "sup3rs3cr3tvalue"')
    assert "secret.assignment" in rule_ids(found)


@pytest.mark.parametrize(
    "content",
    [
        'password = "your-password-here"',
        'api_key = "CHANGEME"',
        'secret = "${VAULT_SECRET}"',
        'token = "process.env.TOKEN"',
        'password = "os.environ[X]"',
        'api_key = "<your key>"',
        'password = "short"',            # 8文字未満
        'password = "example123"',
    ],
)
def test_placeholders_are_not_reported(entry_factory, content: str) -> None:
    assert "secret.assignment" not in rule_ids(scan(entry_factory, "app.py", content))


@pytest.mark.parametrize(
    ("value", "expected"),
    [("s3cr3tvalue", True), ("short", False), ("", False),
     ("your-key", False), ("changeme-now", False), ("dummy-value", False)],
)
def test_looks_like_secret_value(value: str, expected: bool) -> None:
    assert sc.looks_like_secret_value(value) is expected


# ---------------- 危険なコード ----------------
@pytest.mark.parametrize(
    ("relpath", "content", "rule"),
    [
        ("a.py", "eval(user_input)", "code.py_eval"),
        ("a.py", "os.system(cmd)", "code.os_system"),
        ("a.py", "subprocess.run(cmd, shell=True)", "code.subprocess_shell"),
        ("a.js", "child_process.exec(cmd)", "code.node_exec"),
        ("a.py", "pickle.loads(data)", "code.pickle"),
        ("a.py", "yaml.load(f)", "code.yaml_load"),
        ("a.py", "requests.get(u, verify=False)", "code.tls_verify_off_py"),
        ("a.js", "{ rejectUnauthorized: false }", "code.tls_verify_off_node"),
        ("a.sh", "NODE_TLS_REJECT_UNAUTHORIZED=0", "code.tls_env"),
        ("a.py", "hashlib.md5(data)", "code.weak_hash"),
        ("a.js", "el.innerHTML = value", "code.innerhtml"),
        ("a.js", "document.write(x)", "code.document_write"),
        ("a.py", 'cur.execute("SELECT * FROM t WHERE a=" + x)', "code.sql_fstring"),
        ("a.js", "Math.random()", "code.insecure_random"),
        ("a.py", 'url = "http://api.example.com"', "code.http_url"),
        ("a.py", "DEBUG = True", "code.debug_true"),
    ],
)
def test_code_rules(entry_factory, relpath: str, content: str, rule: str) -> None:
    assert rule in rule_ids(scan(entry_factory, relpath, content))


def test_yaml_safe_load_not_flagged(entry_factory) -> None:
    assert "code.yaml_load" not in rule_ids(scan(entry_factory, "a.py", "yaml.load(f, Loader=yaml.SafeLoader)"))


def test_localhost_http_not_flagged(entry_factory) -> None:
    assert "code.http_url" not in rule_ids(scan(entry_factory, "a.py", 'u = "http://127.0.0.1:8787/"'))
    assert "code.http_url" not in rule_ids(scan(entry_factory, "a.py", 'u = "http://localhost:3000/"'))


def test_code_rules_skip_comments(entry_factory) -> None:
    assert "code.os_system" not in rule_ids(scan(entry_factory, "a.py", "# os.system(cmd)"))
    assert "code.node_exec" not in rule_ids(scan(entry_factory, "a.js", "// child_process.exec(x)"))


def test_extension_scoping(entry_factory) -> None:
    """os.system は Python 限定。他拡張子では出さない。"""
    assert "code.os_system" not in rule_ids(scan(entry_factory, "a.txt", "os.system(cmd)"))
    assert "code.os_system" in rule_ids(scan(entry_factory, "a.py", "os.system(cmd)"))


def test_very_long_lines_are_skipped(entry_factory) -> None:
    """minified ファイルの長大行は解析しない。"""
    line = "x" * (sc.MAX_LINE_LEN + 1) + "; eval(y)"
    assert scan(entry_factory, "a.js", line) == []


# ---------------- 設定によるルール制御 ----------------
def test_disabled_rule_is_skipped(entry_factory) -> None:
    rules = RulesConfig(disabled=["code.weak_hash"])
    assert "code.weak_hash" not in rule_ids(scan(entry_factory, "a.py", "hashlib.md5(x)", rules))


def test_disabled_glob_pattern(entry_factory) -> None:
    rules = RulesConfig(disabled=["secret.*"])
    found = scan(entry_factory, "a.py", 'k = "AKIAIOSFODNN7EXAMPLE"\nos.system(c)', rules)
    assert rule_ids(found) == {"code.os_system"}


def test_severity_override(entry_factory) -> None:
    rules = RulesConfig(severity={"code.os_system": "LOW"})
    found = scan(entry_factory, "a.py", "os.system(cmd)", rules)
    assert found[0].severity == "LOW"


def test_severity_override_by_glob(entry_factory) -> None:
    rules = RulesConfig(severity={"code.*": "INFO"})
    found = scan(entry_factory, "a.py", "os.system(cmd)", rules)
    assert found[0].severity == "INFO"


# ---------------- 対象ファイルの判定 ----------------
def test_applies_to(entry_factory) -> None:
    assert sc.applies_to(entry_factory("a.py", ""))
    assert not sc.applies_to(entry_factory("a.png", ""))          # バイナリ
    assert not sc.applies_to(entry_factory("bundle.min.js", ""))  # minified
    assert not sc.applies_to(entry_factory("package-lock.json", ""))  # マニフェスト


def test_findings_carry_location(entry_factory) -> None:
    found = scan(entry_factory, "src/a.py", "x = 1\nos.system(cmd)\n")
    assert found[0].file == "src/a.py"
    assert found[0].line == 2
    assert found[0].category == "static"
    assert found[0].fingerprint
