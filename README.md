# vulnviewer

CISA [Vulnrichment](https://github.com/cisagov/vulnrichment) データセットの軽量ビューワー。
サーバ不要（GitHub Actions + GitHub Pages + クライアントサイドJSのみ）で、
CVE ID / CVSS値 / Exploitation / Automatable / Technical Impact / CVSS Vector /
Vendor / Product / CWE でフィルタ・ソートでき、SSVC Exploitationが
`none → active` / `poc → active` になるまでの日数も表示する。

## 仕組み

1. **`scripts/backfill_history.py`**（ローカルで最初に1回だけ手動実行）
   Vulnrichmentリポジトリの全git履歴をマイニングし、Exploitation値の
   遷移履歴と現在のCVEスナップショットを `data/vulnviewer.db`（SQLite）に構築する。
2. **`.github/workflows/update.yml`**（1日2回、GitHub Actionsが自動実行）
   `scripts/update_incremental.py` で新規コミットのみ差分反映し、
   `scripts/export_json.py` で `docs/data/cves.json` を再生成、
   両ファイルをリポジトリにコミットし直す（これがそのままPagesの更新になる）。
3. **`docs/index.html`**（GitHub Pagesで配信）
   Tabulator.jsが `docs/data/cves.json` を読み込み、フィルタ・ソートは
   すべてブラウザ側で行う。バックエンドAPIは存在しない。

## セットアップ手順

1. このフォルダをGitHubに `vulnviewer` という **Public** リポジトリとしてpush。
2. リポジトリの Settings → Pages で、Source を `Deploy from a branch`、
   Branch を `main` / `/docs` に設定。
3. ローカルで初回バックフィルを実行（時間がかかるので気長に）:
   ```
   pip install -r scripts/requirements.txt
   python scripts/backfill_history.py
   ```
   完了すると `data/vulnviewer.db` が生成される。中断しても再実行すれば
   途中から再開できる（`meta.last_processed_sha` に進捗を保存しているため）。
4. 静的JSONを一度手元で生成して動作確認:
   ```
   python scripts/export_json.py
   python -m http.server --directory docs 8000
   ```
   `http://localhost:8000` を開いてテーブルが表示されることを確認。
5. `data/vulnviewer.db` と `docs/data/cves.json` をコミットしてpush。
6. GitHub ActionsのSecretsは不要（`GITHUB_TOKEN` は自動で使われる）。
   Actions タブから `Update Vulnrichment data` を `workflow_dispatch` で
   一度手動実行し、正常に完走してpushされることを確認してから
   スケジュール実行（1日2回）に任せる。

## 制限事項

- `days_none_to_active` / `days_poc_to_active` は、そのCVEの遷移が
  Vulnrichmentのgit履歴内で実際に観測できた場合のみ計算される。
  履歴上「最初から active/poc だった」CVE（遷移元が観測不可）は `N/A` になる
  （`exploitation_left_censored` フラグで判別可能）。
- SSVC評価自体が存在しないCVE（CNAのみのレコード）は `exploitation` が
  `null` になり、文字列 `"none"` とは区別される。
