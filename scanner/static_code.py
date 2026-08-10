"""静的コード解析スキャナ（ルールベース）。

ハードコードされた秘密情報、危険な関数呼び出し、安全でない実装パターンを
正規表現で検出する。ネットワーク不要でオフライン動作する。
"""
from __future__ import annotations

import re
from typing import List

from .models import Finding
from .util import walk_files, rel, read_lines, BINARY_EXT
import os

# 秘密情報らしき値がプレースホルダ/環境変数参照なら除外するための判定
_PLACEHOLDER = re.compile(
    r"(?i)(xxxx|your[_-]?|example|changeme|placeholder|dummy|sample|<[^>]+>|"
    r"\{\{|\$\{|process\.env|os\.environ|getenv|None|null|redacted|\*\*\*)"
)


def _looks_like_secret_value(val: str) -> bool:
    if not val or len(val) < 8:
        return False
    if _PLACEHOLDER.search(val):
        return False
    return True


# --- 秘密情報ルール（値の形そのもので判定できるもの）--------------------
SECRET_RULES = [
    ("secret.aws_access_key", "CRITICAL", "AWSアクセスキーIDのハードコード",
     re.compile(r"\b(AKIA|ASIA)[0-9A-Z]{16}\b"),
     "AWSアクセスキーIDがソース内に直接埋め込まれています。",
     "キーを直ちに無効化・ローテーションし、環境変数やSecrets Managerで管理してください。"),
    ("secret.private_key", "CRITICAL", "秘密鍵のハードコード",
     re.compile(r"-----BEGIN (?:RSA |EC |DSA |OPENSSH |PGP )?PRIVATE KEY-----"),
     "PEM形式の秘密鍵がリポジトリ内に含まれています。",
     "鍵を失効・再発行し、鍵ファイルはバージョン管理から除外してください。"),
    ("secret.github_token", "HIGH", "GitHubトークンのハードコード",
     re.compile(r"\b(ghp|gho|ghu|ghs|ghr)_[0-9A-Za-z]{36}\b"),
     "GitHubのパーソナルアクセストークンが埋め込まれています。",
     "トークンを失効させ、CIのシークレット機構で注入してください。"),
    ("secret.slack_token", "HIGH", "Slackトークンのハードコード",
     re.compile(r"\bxox[baprs]-[0-9A-Za-z-]{10,}\b"),
     "Slack APIトークンが埋め込まれています。",
     "トークンを失効させ、環境変数で管理してください。"),
    ("secret.google_api_key", "HIGH", "Google APIキーのハードコード",
     re.compile(r"\bAIza[0-9A-Za-z_\-]{35}\b"),
     "Google APIキーが埋め込まれています。",
     "キーを失効・再発行し、利用制限とSecrets管理を行ってください。"),
    ("secret.stripe_key", "CRITICAL", "Stripe秘密鍵のハードコード",
     re.compile(r"\b(sk|rk)_(live|test)_[0-9A-Za-z]{20,}\b"),
     "Stripeの秘密鍵が埋め込まれています。",
     "キーをローテーションし、サーバー側の環境変数で管理してください。"),
    ("secret.jwt", "MEDIUM", "JWTらしき文字列のハードコード",
     re.compile(r"\beyJ[A-Za-z0-9_\-]{10,}\.[A-Za-z0-9_\-]{10,}\.[A-Za-z0-9_\-]{10,}\b"),
     "JWT（署名付きトークン）がソース内に埋め込まれています。",
     "トークンが機密であればローテーションし、コードに固定しないでください。"),
    ("secret.slack_webhook", "HIGH", "Slack Webhook URLのハードコード",
     re.compile(r"https://hooks\.slack\.com/services/[A-Za-z0-9_/]+"),
     "Slack Incoming Webhook URLが埋め込まれています。",
     "Webhookを再発行し、設定値として外出ししてください。"),
]

# 値をキャプチャして中身を検査する代入型シークレット
ASSIGN_SECRET = re.compile(
    r"(?i)(password|passwd|pwd|secret|api[_-]?key|apikey|access[_-]?token|"
    r"auth[_-]?token|client[_-]?secret|private[_-]?key|db[_-]?password)\s*"
    r"[:=]\s*[\"']([^\"']{6,})[\"']"
)

# --- 危険なコードパターン ------------------------------------------------
# (id, severity, title, regex, 対象拡張子(空=全部), description, recommendation)
CODE_RULES = [
    ("code.py_eval", "HIGH", "eval/exec による動的コード実行", re.compile(r"\b(eval|exec)\s*\("),
     {".py", ".js", ".ts", ".rb", ".php"},
     "eval/exec は任意コード実行につながり、入力が信頼できない場合に危険です。",
     "eval/exec を避け、明示的なパースや許可リスト方式に置き換えてください。"),
    ("code.os_system", "HIGH", "シェル経由のOSコマンド実行", re.compile(r"\bos\.system\s*\("),
     {".py"},
     "os.system は文字列をシェルで実行するため、コマンドインジェクションの温床です。",
     "subprocess.run([...], shell=False) を使い、引数を配列で渡してください。"),
    ("code.subprocess_shell", "HIGH", "subprocess shell=True", re.compile(r"shell\s*=\s*True"),
     {".py"},
     "shell=True は外部入力を含む場合にコマンドインジェクションを許します。",
     "shell=False（デフォルト）とし、コマンドと引数を配列で指定してください。"),
    ("code.node_exec", "HIGH", "child_process.exec の使用", re.compile(r"child_process\s*\.\s*exec\s*\(|\brequire\(['\"]child_process['\"]\)\.exec"),
     {".js", ".ts", ".jsx", ".tsx"},
     "child_process.exec はシェルを介すためコマンドインジェクションのリスクがあります。",
     "execFile/spawn を使い、引数を配列で渡してください。"),
    ("code.pickle", "HIGH", "pickle による信頼できないデータの復元", re.compile(r"\bpickle\.(loads|load)\s*\("),
     {".py"},
     "pickle は復元時に任意コードを実行し得ます。信頼できないデータに使うと危険です。",
     "JSON等の安全な形式を用いるか、署名検証を行ってください。"),
    ("code.yaml_load", "MEDIUM", "yaml.load の安全でない使用", re.compile(r"\byaml\.load\s*\((?![^)]*Safe)"),
     {".py"},
     "Loader未指定の yaml.load は任意オブジェクト生成を許します。",
     "yaml.safe_load を使用してください。"),
    ("code.tls_verify_off_py", "HIGH", "TLS証明書検証の無効化 (verify=False)", re.compile(r"verify\s*=\s*False"),
     {".py"},
     "requests等で verify=False とすると中間者攻撃を検知できません。",
     "証明書検証を有効化し、必要なら社内CAを信頼ストアに追加してください。"),
    ("code.tls_verify_off_node", "HIGH", "TLS証明書検証の無効化 (rejectUnauthorized:false)", re.compile(r"rejectUnauthorized\s*:\s*false"),
     {".js", ".ts", ".jsx", ".tsx"},
     "rejectUnauthorized:false はTLS検証を無効化し、通信の改ざんを許します。",
     "検証を有効のままにしてください。"),
    ("code.tls_env", "HIGH", "NODE_TLS_REJECT_UNAUTHORIZED=0", re.compile(r"NODE_TLS_REJECT_UNAUTHORIZED\s*[=:]\s*['\"]?0"),
     set(),
     "プロセス全体のTLS検証を無効化しています。",
     "この設定を削除してください。"),
    ("code.weak_hash", "LOW", "脆弱なハッシュ関数 (MD5/SHA1)", re.compile(r"(?i)(md5|sha1)\s*\(|hashlib\.(md5|sha1)\b"),
     {".py", ".js", ".ts", ".java", ".go", ".rb", ".php"},
     "MD5/SHA1 は衝突耐性が弱く、署名やパスワード保存には不適切です。",
     "SHA-256以上、パスワードにはbcrypt/argon2を使用してください。"),
    ("code.innerhtml", "MEDIUM", "innerHTML への代入 (XSSの恐れ)", re.compile(r"\.innerHTML\s*=|dangerouslySetInnerHTML"),
     {".js", ".ts", ".jsx", ".tsx", ".html", ".vue"},
     "ユーザー入力を innerHTML に流し込むとXSSの原因になります。",
     "textContent や適切なサニタイズ/テンプレートエスケープを使ってください。"),
    ("code.document_write", "LOW", "document.write の使用", re.compile(r"document\.write\s*\("),
     {".js", ".ts", ".html"},
     "document.write は動的な内容注入でXSSやパフォーマンス問題を招きます。",
     "DOM APIやフレームワークのレンダリングを使用してください。"),
    ("code.sql_fstring", "MEDIUM", "SQL文の文字列連結/フォーマット", re.compile(r"(?i)(execute|query)\s*\(\s*f?[\"'].*(SELECT|INSERT|UPDATE|DELETE).*[\"']\s*[%+]|(SELECT|INSERT|UPDATE|DELETE)[^\"';]*[\"']\s*\+\s*\w"),
     {".py", ".js", ".ts", ".java", ".go", ".php", ".rb"},
     "SQL文を文字列連結・フォーマットで組み立てるとSQLインジェクションの恐れがあります。",
     "プレースホルダ（パラメータ化クエリ）を使用してください。"),
    ("code.insecure_random", "LOW", "予測可能な乱数の利用", re.compile(r"\bMath\.random\s*\(|\brandom\.random\s*\("),
     {".js", ".ts", ".py"},
     "Math.random / random は暗号用途に不十分で、トークン等に使うと予測されます。",
     "秘密値には crypto.randomBytes / secrets モジュールを使ってください。"),
    ("code.http_url", "INFO", "平文HTTP URL の使用", re.compile(r"http://(?!localhost|127\.0\.0\.1|0\.0\.0\.0)[\w.-]+"),
     {".py", ".js", ".ts", ".java", ".go", ".rb", ".php", ".yml", ".yaml", ".json", ".env"},
     "暗号化されていないHTTP通信は盗聴・改ざんの対象になります。",
     "可能な限りHTTPSを使用してください。"),
    ("code.debug_true", "LOW", "デバッグモードの有効化", re.compile(r"(?i)\bdebug\s*[:=]\s*True\b|DEBUG\s*=\s*true"),
     {".py", ".env", ".ini", ".cfg"},
     "本番でデバッグモードが有効だと詳細なエラー情報が漏えいします。",
     "本番環境ではDEBUGを無効にしてください。"),
]

# ソースコード拡張子（コメント行での誤検知をなるべく避けるため対象を限定）
_COMMENT_PREFIX = ("#", "//", "*", "/*", "<!--")


def _is_comment(line: str) -> bool:
    s = line.strip()
    return s.startswith(_COMMENT_PREFIX)


def scan(root: str) -> List[Finding]:
    findings: List[Finding] = []
    for path in walk_files(root):
        ext = os.path.splitext(path)[1].lower()
        if ext in BINARY_EXT:
            continue
        base = os.path.basename(path).lower()
        # ロックファイル・minified は静的解析対象外
        if base.endswith(".min.js") or base.endswith(".min.css"):
            continue
        lines = read_lines(path)
        if not lines:
            continue
        relpath = rel(root, path)
        for i, line in enumerate(lines, start=1):
            if len(line) > 1000:  # minified等の長大行はスキップ
                continue

            # 値形状で判定するシークレット
            for rid, sev, title, rx, desc, rec in SECRET_RULES:
                if rx.search(line):
                    findings.append(Finding(
                        category="static", severity=sev, title=title, description=desc,
                        recommendation=rec, file=relpath, line=i, rule_id=rid,
                    ).finalize())

            # 代入型シークレット（値の中身を検査）
            m = ASSIGN_SECRET.search(line)
            if m and _looks_like_secret_value(m.group(2)):
                key = m.group(1)
                findings.append(Finding(
                    category="static", severity="HIGH",
                    title=f"認証情報のハードコード ({key})",
                    description=f"'{key}' に固定値の秘密情報が代入されています。",
                    recommendation="値を環境変数やSecrets管理に移し、コードから削除してください。",
                    file=relpath, line=i, rule_id="secret.assignment",
                ).finalize())

            # 危険なコードパターン
            if _is_comment(line):
                continue
            for rid, sev, title, rx, exts, desc, rec in CODE_RULES:
                if exts and ext not in exts:
                    continue
                if rx.search(line):
                    findings.append(Finding(
                        category="static", severity=sev, title=title, description=desc,
                        recommendation=rec, file=relpath, line=i, rule_id=rid,
                    ).finalize())
    return findings
