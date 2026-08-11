"""設定ファイル診断。

Dockerfile / docker-compose / GitHub Actions / Terraform / Kubernetes /
.env などのセキュリティ上の設定ミスを検出する。オフライン動作。
"""
from __future__ import annotations

import re
from collections.abc import Callable

from ..config import RulesConfig
from ..models import Finding
from .walker import FileEntry

ALL_RULE_IDS: tuple[str, ...] = (
    "docker.user_root", "docker.no_user", "docker.latest_tag", "docker.curl_bash",
    "docker.insecure_download", "docker.secret_env", "docker.add_remote",
    "compose.privileged", "compose.host_network", "compose.expose_all",
    "gha.pr_target", "gha.script_injection", "gha.unpinned_action",
    "tf.open_cidr", "tf.public_acl", "tf.no_encryption",
    "k8s.privileged", "k8s.host_network", "k8s.run_as_root",
    "env.present",
)


class _Collector:
    """ルール ID による無効化を通しつつ Finding を積む小さなヘルパ。"""

    def __init__(self, entry: FileEntry, rules: RulesConfig) -> None:
        self.entry = entry
        self.rules = rules
        self.out: list[Finding] = []

    def add(self, rule_id: str, severity: str, title: str, description: str,
            recommendation: str, line: int, evidence: str) -> None:
        if self.rules.is_disabled(rule_id):
            return
        f = Finding(
            category="config",
            severity=self.rules.severity_for(rule_id, severity),
            title=title,
            rule_id=rule_id,
            description=description,
            recommendation=recommendation,
            file=self.entry.relpath,
            line=line,
            evidence=evidence,
        )
        f.compute_fingerprint()
        self.out.append(f)


# ---------------- Dockerfile ----------------
def _scan_dockerfile(c: _Collector, text: str) -> None:
    has_user = False
    for i, raw in enumerate(text.splitlines(), start=1):
        line = raw.strip()
        low = line.lower()
        if low.startswith("user ") and "root" not in low:
            has_user = True
        if low.startswith("user ") and low.split()[1:2] == ["root"]:
            c.add("docker.user_root", "MEDIUM", "Dockerfile: rootユーザーで実行",
                  "USER root が指定されており、コンテナが特権ユーザーで動作します。",
                  "専用の非rootユーザーを作成し USER で切り替えてください。", i, line)
        if re.search(r"^\s*FROM\s+\S+:latest", line, re.I) or re.search(r"^\s*FROM\s+[^:\s]+\s*$", line, re.I):
            c.add("docker.latest_tag", "LOW", "Dockerfile: イメージタグが可変(latest/未指定)",
                  "ベースイメージのタグが latest または未指定で、再現性と改ざん検知が損なわれます。",
                  "バージョン固定（できれば@sha256ダイジェスト）を指定してください。", i, line)
        if re.search(r"(curl|wget)[^\n|]*\|\s*(sudo\s+)?(sh|bash)", low):
            c.add("docker.curl_bash", "HIGH", "Dockerfile: curl|bash による未検証スクリプト実行",
                  "ネットワークから取得したスクリプトを検証せず実行しています（供給網リスク）。",
                  "スクリプトを固定・検証（チェックサム）してから実行してください。", i, line)
        if "--no-check-certificate" in low or "--insecure" in low:
            c.add("docker.insecure_download", "HIGH", "Dockerfile: TLS検証を無効化",
                  "ダウンロード時に証明書検証を無効化しています。",
                  "検証を有効にしてください。", i, line)
        if re.search(r"(?i)(password|secret|token|api[_-]?key)\s*=", line) and low.startswith(("env", "arg")):
            c.add("docker.secret_env", "HIGH", "Dockerfile: ENV/ARGへの秘密情報埋め込み",
                  "ENV/ARG に秘密情報が直書きされるとイメージ履歴に残ります。",
                  "ビルド時シークレット(--secret)やランタイム注入を使ってください。", i, line)
        if low.startswith("add ") and ("http://" in low or "https://" in low):
            c.add("docker.add_remote", "LOW", "Dockerfile: リモートURLからのADD",
                  "ADD でのリモート取得は検証されず、COPYより推奨されません。",
                  "検証可能な手順でCOPYするか、チェックサムを確認してください。", i, line)
    if not has_user:
        # ファイル全体に対する指摘。evidence はパスにしておく（行内容が無いため）。
        c.add("docker.no_user", "MEDIUM", "Dockerfile: 非rootユーザー未指定",
              "USER 指定がなく、デフォルトのroot権限でコンテナが動作します。",
              "非rootユーザーを作成し USER で切り替えてください。", 0, c.entry.relpath)


# ---------------- docker-compose ----------------
def _scan_compose(c: _Collector, text: str) -> None:
    for i, raw in enumerate(text.splitlines(), start=1):
        low = raw.lower()
        if re.search(r"privileged\s*:\s*true", low):
            c.add("compose.privileged", "HIGH", "compose: privilegedコンテナ",
                  "privileged:true はホストへのほぼ全アクセスを許可します。",
                  "privilegedを外し、必要な機能のみcap_addで付与してください。", i, raw.strip())
        if re.search(r"network_mode\s*:\s*[\"']?host", low):
            c.add("compose.host_network", "MEDIUM", "compose: host ネットワークモード",
                  "ホストネットワーク共有により分離が失われます。",
                  "専用ネットワークを使用してください。", i, raw.strip())
        m = re.search(r"[\"']?0\.0\.0\.0:(\d+):", raw)
        if m:
            c.add("compose.expose_all", "LOW", "compose: 全インターフェースへのポート公開",
                  f"0.0.0.0 でポート{m.group(1)}を公開しており、外部露出の恐れがあります。",
                  "127.0.0.1 へのバインドや適切なFW制御を検討してください。", i, raw.strip())


# ---------------- GitHub Actions ----------------
def _scan_gha(c: _Collector, text: str) -> None:
    for i, raw in enumerate(text.splitlines(), start=1):
        low = raw.lower()
        if "pull_request_target" in low:
            c.add("gha.pr_target", "HIGH", "GitHub Actions: pull_request_target の使用",
                  "pull_request_target は書き込み権限とシークレットをフォークPRに晒す恐れがあります。",
                  "信頼できないコードのチェックアウトを避け、権限を最小化してください。", i, raw.strip())
        if re.search(r"run:.*\$\{\{\s*github\.event\.(issue|pull_request|comment|head)", raw):
            c.add("gha.script_injection", "HIGH",
                  "GitHub Actions: run内でのイベント値の展開(スクリプトインジェクション)",
                  "${{ github.event.* }} を run: に直接展開するとコマンドインジェクションになります。",
                  "値を環境変数(env:)経由で受け、シェルで安全に参照してください。", i, raw.strip())
        if re.search(r"uses:\s*[\w.-]+/[\w.-]+@(main|master)\b", low):
            c.add("gha.unpinned_action", "LOW", "GitHub Actions: サードパーティ Action をブランチ参照",
                  "Actionをmain/masterで参照するとタグ差し替えのリスクがあります。",
                  "コミットSHAでのピン留めを推奨します。", i, raw.strip())


# ---------------- Terraform ----------------
def _scan_terraform(c: _Collector, text: str) -> None:
    for i, raw in enumerate(text.splitlines(), start=1):
        low = raw.lower()
        if "0.0.0.0/0" in raw:
            c.add("tf.open_cidr", "HIGH", "Terraform: 0.0.0.0/0 への開放",
                  "セキュリティグループ等で全世界からのアクセスを許可しています。",
                  "送信元IP/CIDRを必要最小限に絞ってください。", i, raw.strip())
        if re.search(r'acl\s*=\s*"public-read', low):
            c.add("tf.public_acl", "HIGH", "Terraform: 公開ACLの指定",
                  "S3等のACLがpublic-readで、データが公開される恐れがあります。",
                  "非公開ACLとし、必要な公開はCloudFront等で制御してください。", i, raw.strip())
        if re.search(r"encrypt(ed)?\s*=\s*false", low):
            c.add("tf.no_encryption", "MEDIUM", "Terraform: 暗号化の無効化",
                  "ストレージ/ボリュームの暗号化が無効化されています。",
                  "保存時暗号化を有効にしてください。", i, raw.strip())


# ---------------- Kubernetes ----------------
def _scan_k8s(c: _Collector, text: str) -> None:
    if "apiVersion" not in text or "kind" not in text:
        return
    for i, raw in enumerate(text.splitlines(), start=1):
        low = raw.lower()
        if re.search(r"privileged\s*:\s*true", low):
            c.add("k8s.privileged", "HIGH", "Kubernetes: privilegedコンテナ",
                  "securityContextでprivileged:trueが指定されています。",
                  "privilegedを無効化し、必要な権限のみ付与してください。", i, raw.strip())
        if re.search(r"hostnetwork\s*:\s*true", low):
            c.add("k8s.host_network", "MEDIUM", "Kubernetes: hostNetworkの有効化",
                  "hostNetwork:true によりPodがホストのネットワークを共有します。",
                  "必要でなければ無効化してください。", i, raw.strip())
        if re.search(r"runasnonroot\s*:\s*false", low):
            c.add("k8s.run_as_root", "MEDIUM", "Kubernetes: runAsNonRoot=false",
                  "コンテナがrootで実行される設定です。",
                  "runAsNonRoot:true と非root UIDを指定してください。", i, raw.strip())


# ---------------- .env ----------------
def _scan_env(c: _Collector, text: str) -> None:
    c.add("env.present", "MEDIUM", ".env ファイルの存在",
          ".env に秘密情報が含まれる場合、誤ってコミットされると漏えいします。",
          ".gitignore に追加し、秘密情報の混入とコミット履歴を確認してください。",
          0, c.entry.relpath)


def _dispatcher(entry: FileEntry) -> Callable[[_Collector, str], None] | None:
    """このファイルを担当する診断関数を返す。対象外なら None。"""
    low = entry.lname
    if low == "dockerfile" or low.startswith("dockerfile.") or low.endswith(".dockerfile"):
        return _scan_dockerfile
    if re.match(r"docker-compose.*\.ya?ml$", low) or low in ("compose.yml", "compose.yaml"):
        return _scan_compose
    if ".github/workflows/" in entry.relpath and entry.ext in (".yml", ".yaml"):
        return _scan_gha
    if entry.ext == ".tf":
        return _scan_terraform
    if entry.ext in (".yml", ".yaml"):
        return _scan_k8s
    if low == ".env" or low.startswith(".env.") or low.endswith(".env"):
        return _scan_env
    return None


def applies_to(entry: FileEntry) -> bool:
    return _dispatcher(entry) is not None


def scan_file(entry: FileEntry, text: str, rules: RulesConfig) -> list[Finding]:
    fn = _dispatcher(entry)
    if fn is None:
        return []
    collector = _Collector(entry, rules)
    fn(collector, text)
    return collector.out
