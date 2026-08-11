"""設定ファイル診断ルール。"""
from __future__ import annotations

import pytest

from securia.config import RulesConfig
from securia.scan import config_scan as cs


def scan(entry_factory, relpath: str, content: str, rules: RulesConfig | None = None):
    entry = entry_factory(relpath, content)
    return cs.scan_file(entry, content, rules or RulesConfig())


def rule_ids(findings) -> set[str]:
    return {f.rule_id for f in findings}


# ---------------- Dockerfile ----------------
def test_dockerfile_rules(entry_factory) -> None:
    content = (
        "FROM python:latest\n"
        "RUN curl https://x.test/i.sh | bash\n"
        "RUN wget --no-check-certificate https://x.test/f\n"
        "ENV API_KEY=abcdef\n"
        "ADD http://x.test/f /f\n"
        "USER root\n"
    )
    found = rule_ids(scan(entry_factory, "Dockerfile", content))
    assert found >= {
        "docker.latest_tag", "docker.curl_bash", "docker.insecure_download",
        "docker.secret_env", "docker.add_remote", "docker.user_root",
    }


def test_dockerfile_missing_user_is_reported(entry_factory) -> None:
    assert "docker.no_user" in rule_ids(scan(entry_factory, "Dockerfile", "FROM alpine:3.19\n"))


def test_dockerfile_non_root_user_satisfies_check(entry_factory) -> None:
    found = rule_ids(scan(entry_factory, "Dockerfile", "FROM alpine:3.19\nUSER app\n"))
    assert "docker.no_user" not in found
    assert "docker.user_root" not in found


def test_dockerfile_pinned_tag_not_flagged(entry_factory) -> None:
    assert "docker.latest_tag" not in rule_ids(scan(entry_factory, "Dockerfile", "FROM python:3.12.6-slim\n"))


@pytest.mark.parametrize("name", ["Dockerfile", "dockerfile", "Dockerfile.prod", "app.dockerfile"])
def test_dockerfile_naming_variants(entry_factory, name: str) -> None:
    assert "docker.latest_tag" in rule_ids(scan(entry_factory, name, "FROM alpine\n"))


# ---------------- docker-compose ----------------
def test_compose_rules(entry_factory) -> None:
    content = (
        "services:\n  web:\n    privileged: true\n"
        "    network_mode: host\n    ports:\n      - \"0.0.0.0:8080:8080\"\n"
    )
    found = rule_ids(scan(entry_factory, "docker-compose.yml", content))
    assert found == {"compose.privileged", "compose.host_network", "compose.expose_all"}


@pytest.mark.parametrize("name", ["docker-compose.yml", "docker-compose.prod.yaml", "compose.yml"])
def test_compose_naming_variants(entry_factory, name: str) -> None:
    assert "compose.privileged" in rule_ids(scan(entry_factory, name, "    privileged: true\n"))


# ---------------- GitHub Actions ----------------
def test_gha_rules(entry_factory) -> None:
    content = (
        "on: pull_request_target\n"
        "jobs:\n  b:\n    steps:\n"
        "      - uses: actions/checkout@main\n"
        "      - run: echo ${{ github.event.issue.title }}\n"
    )
    found = rule_ids(scan(entry_factory, ".github/workflows/ci.yml", content))
    assert found == {"gha.pr_target", "gha.unpinned_action", "gha.script_injection"}


def test_gha_rules_only_apply_under_workflows_dir(entry_factory) -> None:
    """.github/workflows の外の YAML は Actions として診断しない。"""
    found = rule_ids(scan(entry_factory, "config/ci.yml", "on: pull_request_target\n"))
    assert "gha.pr_target" not in found


def test_pinned_action_sha_not_flagged(entry_factory) -> None:
    content = "      - uses: actions/checkout@8f4b7f84864484a7bf31766abe9204da3cbe65b3\n"
    assert "gha.unpinned_action" not in rule_ids(scan(entry_factory, ".github/workflows/ci.yml", content))


# ---------------- Terraform ----------------
def test_terraform_rules(entry_factory) -> None:
    content = (
        'cidr_blocks = ["0.0.0.0/0"]\n'
        'acl = "public-read"\n'
        "encrypted = false\n"
    )
    found = rule_ids(scan(entry_factory, "main.tf", content))
    assert found == {"tf.open_cidr", "tf.public_acl", "tf.no_encryption"}


def test_terraform_private_acl_not_flagged(entry_factory) -> None:
    assert "tf.public_acl" not in rule_ids(scan(entry_factory, "main.tf", 'acl = "private"\n'))


# ---------------- Kubernetes ----------------
def test_k8s_rules(entry_factory) -> None:
    content = (
        "apiVersion: v1\nkind: Pod\nspec:\n  hostNetwork: true\n"
        "  containers:\n    - securityContext:\n        privileged: true\n"
        "        runAsNonRoot: false\n"
    )
    found = rule_ids(scan(entry_factory, "pod.yaml", content))
    assert found == {"k8s.privileged", "k8s.host_network", "k8s.run_as_root"}


def test_non_k8s_yaml_ignored(entry_factory) -> None:
    """apiVersion/kind が無い YAML は Kubernetes として扱わない。"""
    assert scan(entry_factory, "settings.yaml", "privileged: true\n") == []


# ---------------- .env ----------------
@pytest.mark.parametrize("name", [".env", ".env.local", "prod.env"])
def test_env_file_reported(entry_factory, name: str) -> None:
    assert "env.present" in rule_ids(scan(entry_factory, name, "KEY=value\n"))


# ---------------- 共通 ----------------
def test_unrelated_file_produces_nothing(entry_factory) -> None:
    assert scan(entry_factory, "README.md", "# hello\n") == []
    assert not cs.applies_to(entry_factory("README.md", ""))


def test_disabled_rule_is_skipped(entry_factory) -> None:
    rules = RulesConfig(disabled=["docker.no_user", "docker.latest_tag"])
    assert scan(entry_factory, "Dockerfile", "FROM alpine\n", rules) == []


def test_severity_override(entry_factory) -> None:
    rules = RulesConfig(severity={"tf.open_cidr": "LOW"})
    found = scan(entry_factory, "main.tf", 'cidr = ["0.0.0.0/0"]\n', rules)
    assert found[0].severity == "LOW"


def test_findings_are_categorised_as_config(entry_factory) -> None:
    found = scan(entry_factory, "main.tf", 'cidr = ["0.0.0.0/0"]\n')
    assert found[0].category == "config"
    assert found[0].file == "main.tf"
    assert found[0].line == 1
