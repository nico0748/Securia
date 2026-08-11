# 🛡️ Securia — ローカル脆弱性スキャナ

指定したフォルダを**ローカルだけで**脆弱性スキャンし、ダッシュボードに表示します。
**実行時依存パッケージはゼロ**で、Python 標準ライブラリのみで動作します。

セキュリティツール自身が大量の依存を抱えるのは本末転倒なので、そこは意図的に持ちません。

3 種類のスキャンを一度に実行します。

| 種別 | 内容 |
|------|------|
| **依存関係・SBOM** | `package.json` / `package-lock.json` / `yarn.lock` / `requirements.txt` / `Pipfile.lock` / `poetry.lock` / `go.mod` を解析して SBOM を作り、[OSV.dev](https://osv.dev) と照合して既知の CVE を検出します。 |
| **静的コード解析** | ハードコードされた秘密情報（AWS キー・各種トークン・秘密鍵）、危険な関数呼び出し（`eval` / `os.system` / `pickle` / `shell=True`）、TLS 検証の無効化、脆弱なハッシュ、XSS の恐れなどを検出します。 |
| **設定ファイル診断** | Dockerfile / docker-compose / Terraform / Kubernetes / GitHub Actions / `.env` の設定ミス（root 実行・`0.0.0.0/0` 開放・公開 ACL・秘密情報埋め込み等）を検出します。 |

スキャン結果は SQLite に蓄積され、**前回スキャンとの差分**（新規 / 修正済み / 継続）が出ます。
誤検知は**抑制**して次回以降の集計から外せます。

---

## 必要なもの

**Python 3.11 以上**のみ。追加のパッケージは要りません。

---

## 使い方

### インストールする場合

```bash
pipx install .          # または: pip install .
securia                 # ダッシュボードが起動し、ブラウザが開きます
```

### インストールしない場合

```bash
git clone https://github.com/nico0748/Securia.git
cd Securia
PYTHONPATH=src python3 -m securia
```

`http://127.0.0.1:8787/` が開くので、上部の入力欄に**スキャンしたいフォルダの絶対パス**を入れて
「スキャン実行」を押してください。停止は `Ctrl + C`。

---

## コマンド

```
securia serve         ダッシュボードを起動する（引数なしの既定動作）
securia scan <DIR>    1回スキャンして JSON を出力する
securia history       スキャン履歴を表示する
securia show <ID>     保存済みスキャンの詳細を JSON で出力する
securia suppress      検出を抑制する
securia unsuppress    抑制を解除する
securia suppressions  抑制の一覧を表示する
securia rules         設定で参照できるルール ID を一覧する
securia mcp           MCP サーバーとして動作する（stdio。Claude から使う）
```

### serve

```bash
securia serve --port 9000          # ポートを変更
securia serve --path ~/work/myapp  # 起動時の初期対象フォルダ
securia serve --no-browser         # ブラウザを自動で開かない
```

### scan（CI 向け）

```bash
securia scan ~/work/myapp                      # JSON を標準出力へ
securia scan ~/work/myapp --out report.json    # ファイルへ
securia scan ~/work/myapp --no-osv             # 完全オフライン（CVE 照合なし）
securia scan ~/work/myapp --no-save            # 履歴 DB に残さない
securia scan ~/work/myapp --fail-on high       # HIGH 以上があれば終了コード 1
```

終了コード: `0` 正常 / `1` しきい値以上の検出あり / `2` エラー。

### 抑制（誤検知を消す）

正規表現ベースである以上、誤検知は必ず出ます。画面上の「抑制」ボタン、または CLI から消せます。

```bash
securia suppress 57a7a44fed5ee769 --target ~/work/myapp --reason "テスト用の md5"
securia suppressions --target ~/work/myapp
securia unsuppress 57a7a44fed5ee769 --target ~/work/myapp
```

抑制は fingerprint 単位で、**対象フォルダごと**に効きます。別プロジェクトの同じパターンは消えません。

---

## MCP サーバー（Claude から使う）

Securia は [MCP](https://modelcontextprotocol.io) サーバーとしても動きます。Claude に接続すると、
Claude 自身が「スキャンして、怪しい検出のコードを読んで、誤検知なら抑制する」という調査を
一通り行えるようになります。

プロトコルは標準ライブラリだけで実装しており、**MCP のためだけに依存が増えることはありません**。

### 設定

**Claude Code:**

```bash
claude mcp add securia -- securia mcp
```

**Claude Desktop** — `claude_desktop_config.json` に追記します。

```json
{
  "mcpServers": {
    "securia": {
      "command": "securia",
      "args": ["mcp"]
    }
  }
}
```

インストールせずに使う場合は、リポジトリを指定します。

```json
{
  "mcpServers": {
    "securia": {
      "command": "python3",
      "args": ["-m", "securia", "mcp"],
      "env": { "PYTHONPATH": "/path/to/Securia/src" }
    }
  }
}
```

設定ファイルや DB を指定したい場合は `args` に `--config` / `--db` を足してください。

### 提供するツール

| ツール | 用途 |
|--------|------|
| `securia_scan` | ディレクトリをスキャンし、要約と重要度の高い検出を返す |
| `securia_list_findings` | 検出を重要度・種別・ルール・ファイル・新規かどうかで絞り込む |
| `securia_get_finding` | 1件の詳細と、該当箇所のソースコードを表示する |
| `securia_list_components` | SBOM（依存コンポーネント）を一覧する |
| `securia_scan_history` | 過去のスキャンを一覧する |
| `securia_suppress` / `securia_unsuppress` | 誤検知を抑制・解除する |
| `securia_list_suppressions` | 抑制中の検出を一覧する |
| `securia_list_rules` | 検出ルール ID を一覧する |

リソースとして `securia://rules`（ルール一覧）と `securia://scans/{id}`（スキャン結果の完全な JSON）も
公開しています。

### 設計上の注意

- **文脈の経済性** — 実リポジトリのスキャンは数百件の検出を出します。`securia_scan` は要約と
  上位数件だけを返し、続きは絞り込みとページング付きの `securia_list_findings` で取る作りです。
- **`allowed_roots` は MCP 経由でも効きます。** Claude に任意のディレクトリを読ませることには
  なりません。範囲外を指定するとエラーが返ります。
- **抑制は状態を変えます。** ツールの説明で「抑制する前に `securia_get_finding` で実際のコードを
  読んで確かめること」を指示していますが、`securia_list_suppressions` で何が抑制されたかは
  いつでも確認でき、`securia_unsuppress` で戻せます。
- スキャンは同期実行です。大きなリポジトリではクライアント側が待ちます。

---

## 設定ファイル

`./securia.toml` → `~/.config/securia/config.toml` の順に探し、最初に見つかったものを使います。
`--config FILE` で明示指定もできます。設定が無くても既定値だけで動きます。

`securia.example.toml` に全項目の雛形があります。

```toml
[scan]
# スキャンを許可するディレクトリ。既定はホームディレクトリのみ。
# 空リスト [] にすると制限なしになります（後述のセキュリティの項を参照）。
allowed_roots = ["~/work", "~/src"]
skip_dirs = ["fixtures"]          # 既定の除外リストに追加される
skip_globs = ["*.generated.py"]
max_file_bytes = 2097152
follow_symlinks = false

[rules]
# うるさいルールを黙らせる。glob が使えます。
disabled = ["code.http_url", "code.insecure_random"]

[rules.severity]
# 重要度の上書き
"code.weak_hash" = "info"

[osv]
enabled = true
timeout = 20
max_workers = 8                   # OSV への並列リクエスト数
cache_ttl_days = 7

[server]
port = 8787
open_browser = true
```

ルール ID の一覧は `securia rules` で確認できます。

---

## 動作の前提

- **ローカル専用**: サーバーは `127.0.0.1` にのみバインドします。
- **読み取り専用**: 対象フォルダのファイルを読むだけで、変更はしません。
- **外部に出るもの**: OSV 照合時の**パッケージ名とバージョンだけ**です。コードは送りません。
  オフラインでも SBOM 一覧・静的解析・設定診断は動き、CVE 照合のみスキップされます。
- `node_modules` / `.git` / `venv` / `dist` などは自動的に除外されます。

### データの保存先

スキャン履歴・抑制・OSV キャッシュは SQLite に入ります。

```
~/.local/share/securia/securia.db     # XDG_DATA_HOME があればそちら
```

`SECURIA_DATA_DIR` 環境変数、または `--db FILE` で変更できます。

**検出された行の中身は保存しません。** 秘密情報の検出結果をそのまま書き込むと DB 自体が
秘密情報の置き場になるため、fingerprint 用にハッシュ化した後は捨てています。
画面でコードを表示するときは、その都度ファイルから読み直しています。

---

## セキュリティモデル

ローカルツールでも、ブラウザから触れる HTTP サーバーを立てる以上は攻撃面があります。
`127.0.0.1` へのバインドだけでは不十分です。攻撃者が自分のドメインを `127.0.0.1` に解決させる
**DNS リバインディング**を使うと、被害者のブラウザは同一オリジンとしてこのサーバーへ
リクエストできてしまいます。スキャン結果には「どのファイルの何行目に秘密情報があるか」が
含まれるため、実質的な情報漏洩経路になります。

そこで次の多層防御をかけています。

| 対策 | 目的 |
|------|------|
| **Host ヘッダ検証** | リバインドされたリクエストは Host が攻撃者のドメインになるため弾けます。主防御。 |
| **起動時トークン** | 起動ごとに生成し、ページに埋め込みます。全 API 呼び出しに必須。同一オリジンでないと読めません。 |
| **Origin ヘッダ検証** | クロスオリジンからの API 呼び出しを拒否します。 |
| **`allowed_roots`** | スキャン対象を許可ディレクトリ配下に限定します。 |
| **資格情報ディレクトリの拒否** | `.ssh` / `.aws` / `.gnupg` などは許可ルート内でもスキャンしません。 |
| **CSP** | `default-src 'none'` を基本に、外部リソースを一切読み込みません。 |

`allowed_roots` を `[]`（制限なし）にすると1層目が外れます。設定の意味を理解した上でどうぞ。

---

## 構成

```
Securia/
├── pyproject.toml
├── securia.example.toml
├── src/securia/
│   ├── cli.py            # サブコマンド
│   ├── config.py         # securia.toml
│   ├── engine.py         # スキャンのオーケストレーション（1パス走査）
│   ├── models.py         # Finding / Component と fingerprint
│   ├── osv.py            # OSV クライアント（並列・キャッシュ・勧告の統合）
│   ├── paths.py          # データディレクトリとパス検証
│   ├── store.py          # SQLite（履歴・抑制・キャッシュ）
│   ├── diff.py           # 前回との差分
│   ├── jobs.py           # 非同期スキャンと進捗配信
│   ├── server.py         # HTTP サーバーとセキュリティ検査
│   ├── mcp/
│   │   ├── protocol.py     # JSON-RPC 2.0 と stdio 転送
│   │   ├── server.py       # MCP のライフサイクルとメソッド
│   │   └── tools.py        # Claude へ公開するツールとリソース
│   ├── scan/
│   │   ├── walker.py       # ディレクトリ走査とファイル読み込み
│   │   ├── dependency.py   # マニフェスト/ロックファイルのパーサ
│   │   ├── static_code.py  # 静的コード解析ルール
│   │   ├── config_scan.py  # 設定ファイル診断ルール
│   │   └── cvss.py         # CVSS v3 スコア算出
│   └── web/                # ダッシュボード (HTML / CSS / JS)
└── tests/                  # pytest
```

### 検出の同一性について

検出の識別子（fingerprint）には**行番号を含めません**。代わりに一致した行の内容を
ハッシュ化して使います。こうしないと、ファイルの先頭に1行足しただけで全ての検出が
「新規」に化けて差分機能が使いものにならなくなります。中身が変われば別の検出になります。

---

## 開発

```bash
pip install -e ".[dev]"
pytest                    # テスト
ruff check src tests      # Linter
```

### 拡張のヒント

- 検出ルールの追加は `src/securia/scan/static_code.py` の `SECRET_RULES` / `CODE_RULES`、
  `src/securia/scan/config_scan.py` の各 `_scan_*` 関数を編集します。
  ルールはデータクラスで宣言するだけで、設定による無効化と重要度上書きは自動で効きます。
- 対応エコシステムを増やす場合は `src/securia/scan/dependency.py` にパーサを追加し、
  `_PARSERS` に登録してください（OSV は Maven / RubyGems / crates.io / NuGet 等にも対応）。

---

## ライセンス

MIT License — 詳細は [LICENSE](LICENSE) を参照してください。
