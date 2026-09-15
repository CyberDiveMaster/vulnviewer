"""Syncs EPSS (Exploit Prediction Scoring System) scores from FIRST.org into
data/vulnviewer.db, on its own daily schedule -- separate from the
Vulnrichment git-mining pipeline these other columns come from.

FIRST.org recalculates EPSS for essentially every scored CVE once a day
(not just newly-changed ones), so unlike an incremental Vulnrichment poll,
every run here touches most rows in the `cve` table. Run this at most once
a day (see .github/workflows/vulnrichment-sync.yml's second cron entry) --
running it as often as the 10-minute Vulnrichment poll would pointlessly
re-download the same ~20MB file and touch nearly every row on every poll.

The CSV always contains many more CVEs than Vulrichment tracks (EPSS scores
essentially the entire CVE list); rows for CVE IDs not already in our `cve`
table are silently skipped (see db.update_epss_scores) rather than creating
placeholder rows with none of this dataset's other fields populated.
"""

import argparse
import csv
import gzip
import io
import sys
import urllib.request
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parent))

from common import db, pipeline

PROJECT_ROOT = Path(__file__).resolve().parent.parent
DEFAULT_DB_PATH = PROJECT_ROOT / "data" / "vulnviewer.db"
EPSS_URL = "https://epss.empiricalsecurity.com/epss_scores-current.csv.gz"


def fetch_epss_rows(url):
    """Yields (epss_score, epss_percentile, cve_id) tuples -- that column
    order matches db.update_epss_scores' positional UPDATE statement.
    The file always starts with a "#model_version:...,score_date:..."
    comment line before the real CSV header (see FIRST.org docs), so the
    header row is found by content rather than assumed to be line 1."""
    req = urllib.request.Request(url, headers={"User-Agent": "vulnviewer/1.0"})
    with urllib.request.urlopen(req) as resp:
        raw = resp.read()

    text = gzip.decompress(raw).decode("utf-8")
    lines = text.splitlines()
    header_idx = next(i for i, line in enumerate(lines) if line.startswith("cve,"))

    reader = csv.DictReader(io.StringIO("\n".join(lines[header_idx:])))
    for row in reader:
        yield (float(row["epss"]), float(row["percentile"]), row["cve"])


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--db", type=Path, default=DEFAULT_DB_PATH)
    parser.add_argument("--url", default=EPSS_URL)
    args = parser.parse_args()

    conn = db.connect(args.db)
    db.init_schema(conn)

    print(f"Fetching EPSS scores from {args.url} ...")
    rows = list(fetch_epss_rows(args.url))
    print(f"Downloaded {len(rows)} EPSS scores. Updating matching CVEs...")

    db.update_epss_scores(conn, rows)
    updated = conn.total_changes
    db.meta_set(conn, "last_epss_sync_at", pipeline.now_iso())
    conn.commit()
    conn.close()

    print(f"EPSS sync complete. {updated} rows in our dataset matched and were updated.")


if __name__ == "__main__":
    main()
