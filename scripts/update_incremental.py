"""Scheduled (GitHub Actions) incremental update job.

Each run:
  1. Fetches new commits on the vulnrichment repo since last_processed_sha.
  2. Mines only the Exploitation-relevant commits in that new range.
  3. Re-ingests the current snapshot for every JSON file touched in that
     range (picks up CVSS/vendor/CWE/date changes independent of Exploitation).
  4. Recomputes derived columns only for CVEs touched this run.
  5. Advances meta.last_processed_sha to the new tip.

If meta.last_processed_sha is missing -- e.g. the GitHub Actions cache for
data/vulnviewer.db was never populated (its very first run ever, or the
cache was evicted) -- this falls back to a full history mine (same as
backfill_history.py) rather than failing. Actions jobs default to a 6-hour
timeout, comfortably enough for this one-time bootstrap.
"""

import argparse
import sys
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parent))

from common import db, git_mine, pipeline

PROJECT_ROOT = Path(__file__).resolve().parent.parent
DEFAULT_REPO_URL = "https://github.com/cisagov/vulnrichment.git"
DEFAULT_BRANCH = "develop"
DEFAULT_CLONE_DIR = PROJECT_ROOT / "vendor_repo_cache" / "vulnrichment"
DEFAULT_DB_PATH = PROJECT_ROOT / "data" / "vulnviewer.db"


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--repo-url", default=DEFAULT_REPO_URL)
    parser.add_argument("--branch", default=DEFAULT_BRANCH)
    parser.add_argument("--clone-dir", type=Path, default=DEFAULT_CLONE_DIR)
    parser.add_argument("--db", type=Path, default=DEFAULT_DB_PATH)
    args = parser.parse_args()

    conn = db.connect(args.db)
    db.init_schema(conn)

    print(f"Cloning/using {args.repo_url} at {args.clone_dir} ...")
    git_mine.clone_if_missing(args.clone_dir, args.repo_url, branch=args.branch)
    git_mine.fetch(args.clone_dir, branch=args.branch)
    until_ref = f"origin/{args.branch}"
    tip_sha = git_mine.get_tip_sha(args.clone_dir, ref=until_ref)

    last_sha = db.meta_get(conn, "last_processed_sha")
    if not last_sha:
        print("No baseline found (meta.last_processed_sha unset) -- bootstrapping via full history mine.")
        pipeline.run_full_mine(conn, args.clone_dir, until_ref, tip_sha)
        conn.close()
        print(f"Bootstrap complete. last_processed_sha={tip_sha}")
        return

    if tip_sha == last_sha:
        print("No new commits since last run. Nothing to do.")
        conn.close()
        return

    print(f"Advancing from {last_sha[:10]} to {tip_sha[:10]}")

    touched_by_history = pipeline.mine_exploitation_history(conn, args.clone_dir, until_ref, last_sha)

    touched_files = git_mine.list_touched_files(args.clone_dir, last_sha, until_ref=until_ref)
    touched_by_snapshot = pipeline.ingest_snapshot(conn, args.clone_dir, tip_sha, touched_files)

    all_touched = touched_by_history | touched_by_snapshot
    print(f"Recomputing derived columns for {len(all_touched)} touched CVEs...")
    pipeline.recompute_derived_for(conn, all_touched)

    db.meta_set(conn, "last_processed_sha", tip_sha)
    db.meta_set(conn, "last_incremental_run_at", pipeline.now_iso())
    conn.commit()
    conn.close()

    print(f"Incremental update complete. last_processed_sha={tip_sha}")


if __name__ == "__main__":
    main()
