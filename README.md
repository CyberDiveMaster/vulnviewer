# vulnviewer

CISA [Vulnrichment](https://github.com/cisagov/vulnrichment) データセットの軽量ビューワー。
サーバ不要（GitHub Actions + GitHub Pages + クライアントサイドJSのみ）で、
CVE ID / CVSS値 / Exploitation / Automatable / Technical Impact / CVSS Vector /
Vendor / Product / CWE でフィルタ・ソートでき、SSVC Exploitationが
`none → active` / `poc → active` になるまでの日数も表示する。

実データは約162,000件のCVEを含み、SQLite DBで約180MB、JSON化すると約150MB
になる（GitHubの1ファイル100MB push制限を超える）。そのため
`data/vulnviewer.db` は**Gitにコミットしない**。GitHub Actionsのキャッシュ
だけで永続化し、Pagesに置くのはgzip圧縮した`docs/data/cves.json.gz`
（約10MB）のみで、ブラウザ側で解凍してから表示する。

## 仕組み

1. **`scripts/backfill_history.py`**（ローカルで最初に1回だけ手動実行）
   Vulnrichmentリポジトリの全git履歴をマイニングし、Exploitation値の
   遷移履歴と現在のCVEスナップショットをローカルの `data/vulnviewer.db`
   （SQLite、Gitには含めない）に構築する。
2. **`.github/workflows/update.yml`**（1日2回、GitHub Actionsが自動実行）
   `data/vulnviewer.db` と Vulnrichmentのクローンを Actions キャッシュから
   復元 → `scripts/update_incremental.py` で新規コミットのみ差分反映 →
   `scripts/export_json.py` でgzip圧縮した `docs/data/cves.json.gz` を再生成
   → それだけをリポジトリにコミット（これがそのままPagesの更新になる）→
   両キャッシュを保存し直す。
3. **`docs/index.html`**（GitHub Pagesで配信）
   `cves.json.gz` を取得し、ブラウザ標準の`DecompressionStream`で解凍後、
   Tabulator.jsに読み込ませる。フィルタ・ソートはすべてブラウザ側で行う。
   バックエンドAPIは存在しない。

## セットアップ手順

1. このフォルダをGitHubに `vulnviewer` という **Public** リポジトリとしてpush。
2. リポジトリの Settings → Pages で、Source を `Deploy from a branch`、
   Branch を `main` / `/docs` に設定。
3. ローカルで初回バックフィルを実行（実際のVulnrichmentリポジトリは
   16万ファイル超・クローンだけで相応に時間がかかる）:
   ```
   pip install -r scripts/requirements.txt
   python scripts/backfill_history.py
   ```
   完了すると（Gitにはコミットされない）ローカルの `data/vulnviewer.db` が
   生成される。中断しても再実行すれば途中から再開できる
   （`meta.last_processed_sha` に進捗を保存しているため）。
4. （任意・一時確認）静的JSONを一度手元で生成してブラウザ表示を確認したい場合のみ:
   ```
   python scripts/export_json.py
   python -m http.server --directory docs 8000
   ```
   `http://localhost:8000` を開いてテーブルが表示されることを確認。
   **このローカルサーバは確認用の一時的なものであり、本番運用では一切不要。**
   実際の公開・更新はGitHub Actions + GitHub Pagesのみで完結する。
5. GitHub ActionsのSecretsは不要（`GITHUB_TOKEN` は自動で使われる）。
   まずActions タブから `Update Vulnrichment data` を **手動実行
   （workflow_dispatch）**する。この最初の1回は `data/vulnviewer.db` の
   Actionsキャッシュがまだ存在しないため、Actions環境内で改めて
   Vulnrichmentの全履歴マイニングが走る（ローカルのDBはActionsには
   引き継がれない設計のため）。正常に完走してpushされることを確認してから、
   以降はスケジュール実行（1日2回）に任せる。

## 制限事項

- `data/vulnviewer.db` はGitHub Actionsのキャッシュのみで永続化している。
  キャッシュが失効・削除された場合（長期間未使用、容量上限超過など）は、
  次回実行時に一からVulnrichmentの全履歴マイニングをやり直すことになる
  （データが壊れることはないが、その回だけ処理時間が伸びる）。
- `days_none_to_active` / `days_poc_to_active` は、そのCVEの遷移が
  Vulnrichmentのgit履歴内で実際に観測できた場合のみ計算される。
  履歴上「最初から active/poc だった」CVE（遷移元が観測不可）は `N/A` になる
  （`exploitation_left_censored` フラグで判別可能）。
- SSVC評価自体が存在しないCVE（CNAのみのレコード）は `exploitation` が
  `null` になり、文字列 `"none"` とは区別される。
