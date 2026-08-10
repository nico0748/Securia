"""設定ファイル診断スキャナ。

Dockerfile / docker-compose / GitHub Actions / Terraform / Kubernetes /
.env などのセキュリティ上の設定ミスを検出する。オフライン動作。
"""
from __future__ import annotations

import os
import re
from typing import List

from .models import Finding
from .util import walk_files, rel, read_lines, read_text


def _add(findings, **kw):
    findings.append(Finding(category="config", **kw).finalize())


# ---------------- Dockerfile ----------------
def scan_dockerfile(root, path, findings):
    relpath = rel(root, path)
    lines = read_lines(path)
    has_user = False
    for i, raw in enumerate(lines, start=1):
        line = raw.strip()
        low = line.lower()
        if low.startswith("user ") and "root" not in low:
            has_user = True
        if low.startswith("user ") and low.split()[1:2] == ["root"]:
            _add(findings, severity="MEDIUM", title="Dockerfile: rootユーザーで実行",
                 description="USER root が指定されており、コンテナが特権ユーザーで動作します。",
                 recommendation="専用の非rootユーザーを作成し USER で切り替えてください。",
                 file=relpath, line=i, rule_id="docker.user_root")
        if re.search(r"^\s*FROM\s+\S+:latest", line, re.I) or re.search(r"^\s*FROM\s+[^:\s]+\s*$", line, re.I):
            _add(findings, severity="LOW", title="Dockerfile: イメージタグが可変(latest/未指定)",
                 description="ベースイメージのタグが latest または未指定で、再現性と改ざん検知が損なわれます。",
                 recommendation="バージョン固定（できれば@sha256ダイジェスト）を指定してください。",
                 file=relpath, line=i, rule_id="docker.latest_tag")
        if re.search(r"curl[^\n|]*\|\s*(sudo\s+)?(sh|bash)", low) or re.search(r"wget[^\n|]*\|\s*(sudo\s+)?(sh|bash)", low):
            _add(findings, severity="HIGH", title="Dockerfile: curl|bash による未検証スクリプト実行",
                 description="ネットワークから取得したスクリプトを検証せず実行しています（供給網リスク）。",
                 recommendation="スクリプトを固定・検証（チェックサム）してから実行してください。",
                 file=relpath, line=i, rule_id="docker.curl_bash")
        if "--no-check-certificate" in low or "--insecure" in low:
            _add(findings, severity="HIGH", title="Dockerfile: TLS検証を無効化",
                 description="ダウンロード時に証明書検証を無効化しています。",
                 recommendation="検証を有効にしてください。",
                 file=relpath, line=i, rule_id="docker.insecure_download")
        if re.search(r"(?i)(password|secret|token|api[_-]?key)\s*=", line) and low.startswith(("env", "arg")):
            _add(findings, severity="HIGH", title="Dockerfile: ENV/ARGへの秘密情報埋め込み",
                 description="ENV/ARG に秘密情報が直書きされるとイメージ履歴に残ります。",
                 recommendation="ビルド時シークレット(--secret)やランタイム注入を使ってください。",
                 file=relpath, line=i, rule_id="docker.secret_env")
        if low.startswith("add ") and ("http://" in low or "https://" in low):
            _add(findings, severity="LOW", title="Dockerfile: リモートURLからのADD",
                 description="ADD でのリモート取得は検証されず、COPYより推奨されません。",
                 recommendation="検証可能な手順でCOPYするか、チェックサムを確認してください。",
                 file=relpath, line=i, rule_id="docker.add_remote")
    if not has_user:
        _add(findings, severity="MEDIUM", title="Dockerfile: 非rootユーザー未指定",
             description="USER 指定がなく、デフォルトのroot権限でコンテナが動作します。",
             recommendation="非rootユーザーを作成し USER で切り替えてください。",
             file=relpath, line=0, rule_id="docker.no_user")


# ---------------- docker-compose ----------------
def scan_compose(root, path, findings):
    relpath = rel(root, path)
    for i, raw in enumerate(read_lines(path), start=1):
        low = raw.lower()
        if re.search(r"privileged\s*:\s*true", low):
            _add(findings, severity="HIGH", title="compose: privilegedコンテナ",
                 description="privileged:true はホストへのほぼ全アクセスを許可します。",
                 recommendation="privilegedを外し、必要な機能のみcap_addで付与してください。",
                 file=relpath, line=i, rule_id="compose.privileged")
        if re.search(r"network_mode\s*:\s*[\"']?host", low):
            _add(findings, severity="MEDIUM", title="compose: host ネットワークモード",
                 description="ホストネットワーク共有により分離が失われます。",
                 recommendation="専用ネットワークを使用してください。",
                 file=relpath, line=i, rule_id="compose.host_network")
        m = re.search(r"[\"']?0\.0\.0\.0:(\d+):", raw)
        if m:
            _add(findings, severity="LOW", title="compose: 全インターフェースへのポート公開",
                 description=f"0.0.0.0 でポート{m.group(1)}を公開しており、外部露出の恐れがあります。",
                 recommendation="127.0.0.1 へのバインドや適切なFW制御を検討してください。",
                 file=relpath, line=i, rule_id="compose.expose_all")


# ---------------- GitHub Actions ----------------
def scan_gha(root, path, findings):
    relpath = rel(root, path)
    text = read_text(path)
    lines = text.splitlines()
    for i, raw in enumerate(lines, start=1):
        low = raw.lower()
        if "pull_request_target" in low:
            _add(findings, severity="HIGH", title="GitHub Actions: pull_request_target の使用",
                 description="pull_request_target は書き込み権限とシークレットをフォークPRに晒す恐れがあります。",
                 recommendation="信頼できないコードのチェックアウトを避け、権限を最小化してください。",
                 file=relpath, line=i, rule_id="gha.pr_target")
        if re.search(r"run:.*\$\{\{\s*github\.event\.(issue|pull_request|comment|head)", raw):
            _add(findings, severity="HIGH", title="GitHub Actions: run内でのイベント値の展開(スクリプトインジェクション)",
                 description="${{ github.event.* }} を run: に直接展開するとコマンドインジェクションになります。",
                 recommendation="値を環境変数(env:)経由で受け、シェルで安全に参照してください。",
                 file=relpath, line=i, rule_id="gha.script_injection")
        if re.search(r"uses:\s*[\w.-]+/[\w.-]+@(main|master)\b", low):
            _add(findings, severity="LOW", title="GitHub Actions: サードパーティ Action をブランチ参照",
                 description="Actionをmain/masterで参照するとタグ差し替えのリスクがあります。",
                 recommendation="コミットSHAでのピン留めを推奨します。",
                 file=relpath, line=i, rule_id="gha.unpinned_action")


# ---------------- Terraform ----------------
def scan_terraform(root, path, findings):
    relpath = rel(root, path)
    for i, raw in enumerate(read_lines(path), start=1):
        low = raw.lower()
        if "0.0.0.0/0" in raw:
            _add(findings, severity="HIGH", title="Terraform: 0.0.0.0/0 への開放",
                 description="セキュリティグループ等で全世界からのアクセスを許可しています。",
                 recommendation="送信元IP/CIDRを必要最小限に絞ってください。",
                 file=relpath, line=i, rule_id="tf.open_cidr")
        if re.search(r'acl\s*=\s*"public-read', low) or re.search(r'acl\s*=\s*"public-read-write', low):
            _add(findings, severity="HIGH", title="Terraform: 公開ACLの指定",
                 description="S3等のACLがpublic-readで、データが公開される恐れがあります。",
                 recommendation="非公開ACLとし、必要な公開はCloudFront等で制御してください。",
                 file=relpath, line=i, rule_id="tf.public_acl")
        if re.search(r"encrypt(ed)?\s*=\s*false", low):
            _add(findings, severity="MEDIUM", title="Terraform: 暗号化の無効化",
                 description="ストレージ/ボリュームの暗号化が無効化されています。",
                 recommendation="保存時暗号化を有効にしてください。",
                 file=relpath, line=i, rule_id="tf.no_encryption")


# ---------------- Kubernetes ----------------
def scan_k8s(root, path, findings):
    relpath = rel(root, path)
    text = read_text(path)
    if "apiVersion" not in text or "kind" not in text:
        return
    for i, raw in enumerate(text.splitlines(), start=1):
        low = raw.lower()
        if re.search(r"privileged\s*:\s*true", low):
            _add(findings, severity="HIGH", title="Kubernetes: privilegedコンテナ",
                 description="securityContextでprivileged:trueが指定されています。",
                 recommendation="privilegedを無効化し、必要な権限のみ付与してください。",
                 file=relpath, line=i, rule_id="k8s.privileged")
        if re.search(r"hostnetwork\s*:\s*true", low):
            _add(findings, severity="MEDIUM", title="Kubernetes: hostNetworkの有効化",
                 description="hostNetwork:true によりPodがホストのネットワークを共有します。",
                 recommendation="必要でなければ無効化してください。",
                 file=relpath, line=i, rule_id="k8s.host_network")
        if re.search(r"runasnonroot\s*:\s*false", low):
            _add(findings, severity="MEDIUM", title="Kubernetes: runAsNonRoot=false",
                 description="コンテナがrootで実行される設定です。",
                 recommendation="runAsNonRoot:true と非root UIDを指定してください。",
                 file=relpath, line=i, rule_id="k8s.run_as_root")


# ---------------- .env / 汎用 ----------------
def scan_env(root, path, findings):
    relpath = rel(root, path)
    _add(findings, severity="MEDIUM", title=".env ファイルの存在",
         description=".env に秘密情報が含まれる場合、誤ってコミットされると漏えいします。",
         recommendation=".gitignore に追加し、秘密情報の混入とコミット履歴を確認してください。",
         file=relpath, line=0, rule_id="env.present")


def scan(root: str) -> List[Finding]:
    findings: List[Finding] = []
    for path in walk_files(root):
        name = os.path.basename(path)
        low = name.lower()
        dirpath = os.path.dirname(path).replace("\\", "/")
        ext = os.path.splitext(name)[1].lower()

        if low == "dockerfile" or low.startswith("dockerfile.") or low.endswith(".dockerfile"):
            scan_dockerfile(root, path, findings)
        elif re.match(r"docker-compose.*\.ya?ml$", low) or low in ("compose.yml", "compose.yaml"):
            scan_compose(root, path, findings)
        elif "/.github/workflows" in dirpath and ext in (".yml", ".yaml"):
            scan_gha(root, path, findings)
        elif ext == ".tf":
            scan_terraform(root, path, findings)
        elif ext in (".yml", ".yaml"):
            scan_k8s(root, path, findings)
        elif low == ".env" or low.startswith(".env.") or low.endswith(".env"):
            scan_env(root, path, findings)
    return findings
