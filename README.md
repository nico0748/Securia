# 🛡️ Securia Local — ローカル脆弱性スキャナ

指定したフォルダ内のアプリケーションを、ローカルで脆弱性スキャンして
Securia 風のダッシュボードで表示するツールです。
**Python 標準ライブラリのみ**で動作し、追加インストールは不要です。

3 種類のスキャンを一度に実行します。

| 種別 | 内容 |
|------|------|
| **依存関係・SBOM** | `package.json` / `package-lock.json` / `yarn.lock` / `requirements.txt` / `Pipfile.lock` / `poetry.lock` / `go.mod` などを解析して SBOM を作成し、[OSV.dev](https://osv.dev) の脆弱性データベースと照合して既知の CVE を検出します。 |
| **静的コード解析** | ハードコードされた秘密情報（AWS キー・トークン・秘密鍵など）、危険な関数呼び出し（`eval` / `os.system` / `pickle` / `shell=True` 等）、TLS 検証の無効化、脆弱なハッシュ、XSS の恐れなどを検出します。 |
| **設定ファイル診断** | Dockerfile / docker-compose / Terraform / Kubernetes / GitHub Actions / `.env` のセキュリティ設定ミス（root 実行・`0.0.0.0/0` 開放・公開 ACL・秘密情報埋め込み等）を検出します。 |

---

## 使い方（最短）

Python 3.8 以上が入っていれば、それだけで動きます。

```bash
# 1. 解凍したフォルダに移動
cd securia-local

# 2. 起動（ブラウザが自動で開きます）
python3 run.py
```

ブラウザで `http://127.0.0.1:8787/` が開くので、上部の入力欄に
**スキャンしたいフォルダの絶対パス**を入れて「スキャン実行」を押してください。

> 停止するにはターミナルで `Ctrl + C`。

---

## オプション

```bash
python3 run.py --port 9000            # ポートを変更
python3 run.py --path ~/work/myapp    # 起動時の初期対象フォルダを指定
python3 run.py --no-browser           # ブラウザを自動で開かない
```

### CLI モード（サーバーを立てずに実行）

```bash
python3 run.py --cli ~/work/myapp                 # 結果を JSON で標準出力
python3 run.py --cli ~/work/myapp --out report.json  # JSON をファイルに保存
```

CI に組み込んで JSON を後段で処理する、といった使い方もできます。

---

## 動作の前提・注意

- **インターネット接続**: 依存関係の CVE 照合には OSV.dev への通信が必要です。
  オフラインの場合でも SBOM 一覧・静的解析・設定診断は動作し、CVE 照合のみスキップされます
  （ダッシュボード上部に通知が出ます）。
- **ローカル専用**: サーバーは `127.0.0.1`（自分の PC のみ）にバインドされ、外部には公開されません。
- **読み取り専用**: 対象フォルダのファイルを読み取るだけで、変更・送信は行いません。
  スキャン内容はすべて手元で処理されます（送信されるのはパッケージ名とバージョンのみ、OSV 照合時）。
- `node_modules` / `.git` / `venv` / `dist` などの大きなディレクトリは自動的に除外されます。

---

## 構成

```
securia-local/
├── run.py                 # 起動スクリプト（HTTPサーバー / CLI）
├── run.sh                 # 起動用ラッパー（bash）
├── web/
│   └── index.html         # ダッシュボード UI（単一ファイル）
├── scanner/
│   ├── __init__.py        # スキャン統合・集計
│   ├── dependency.py      # 依存関係・SBOM・OSV照合
│   ├── static_code.py     # 静的コード解析（ルールベース）
│   ├── config_scan.py     # 設定ファイル診断
│   ├── cvss.py            # CVSS v3 スコア算出
│   ├── models.py          # データモデル
│   └── util.py            # ファイル探索ユーティリティ
├── .gitignore
├── LICENSE                # MIT
└── README.md
```

---

## 拡張のヒント

- 検出ルールの追加は `scanner/static_code.py` の `SECRET_RULES` / `CODE_RULES`、
  `scanner/config_scan.py` の各 `scan_*` 関数を編集するだけです。
- 対応エコシステムを増やす場合は `scanner/dependency.py` にパーサを追加してください
  （OSV は Maven / RubyGems / crates.io / NuGet 等にも対応しています）。

## ライセンス

MIT License — 詳細は [LICENSE](LICENSE) を参照してください。自由に改変してご利用ください。
