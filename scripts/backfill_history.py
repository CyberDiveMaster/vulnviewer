"""One-time (run locally, not in CI) full-history mining job.

Clones cisagov/vulnrichment, walks its ENTIRE commit history once to build
the Exploitation state-transition log, then ingests the current snapshot of
every CVE file. Produces the initial data/vulnviewer.db that gets committed
to this repo; after that, update_incremental.py takes over for ongoing runs.

Usage:
    python scripts/backfill_history.py

Safe to interrupt and re-run: progress checkpoints into meta.last_processed_sha
as it goes, and exploitation_history has a UNIQUE(cve_id, commit_sha)
constraint so re-processing an already-seen commit is a no-op.
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

    print(f"Cloning/using {args.repo_url} at {args.clone_dir} ...")
    git_mine.clone_if_missing(args.clone_dir, args.repo_url, branch=args.branch)
    git_mine.fetch(args.clone_dir, branch=args.branch)
    until_ref = f"origin/{args.branch}"
    tip_sha = git_mine.get_tip_sha(args.clone_dir, ref=until_ref)
    print(f"Tip of {until_ref} is {tip_sha}")

    conn = db.connect(args.db)
    db.init_schema(conn)

    pipeline.run_full_mine(conn, args.clone_dir, until_ref, tip_sha)
    conn.close()

    print(f"Backfill complete. last_processed_sha={tip_sha}")
    print(f"Database written to {args.db}")


if __name__ == "__main__":
    main()
