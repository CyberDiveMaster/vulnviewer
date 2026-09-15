"""One-off/occasional maintenance: re-parses and re-ingests the CURRENT
snapshot for every CVE file at the tip, using whatever cve_parser.py's
latest logic is, and recomputes every CVE's derived history-based columns
(first_active_date/days_publish_to_active) using whatever db.py's latest
recompute_derived() logic is. Useful after fixing a parsing bug (e.g. CWE
data that ADP supplies but CNA's own problemTypes entry omits) or a
derived-column bug, so already-ingested CVEs get corrected retroactively,
not just ones touched by future commits.

Does NOT touch exploitation_history itself or meta.last_processed_sha --
run update_incremental.py first to catch up normally, then this to refresh
every CVE's current-state and derived fields with the corrected logic.
"""

import argparse
import sys
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parent))

from common import db, git_mine, pipeline

PROJECT_ROOT = Path(__file__).resolve().parent.parent
DEFAULT_BRANCH = "develop"
DEFAULT_CLONE_DIR = PROJECT_ROOT / "vendor_repo_cache" / "vulnrichment"
DEFAULT_DB_PATH = PROJECT_ROOT / "data" / "vulnviewer.db"


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--clone-dir", type=Path, default=DEFAULT_CLONE_DIR)
    parser.add_argument("--db", type=Path, default=DEFAULT_DB_PATH)
    parser.add_argument("--branch", default=DEFAULT_BRANCH)
    args = parser.parse_args()

    git_mine.fetch(args.clone_dir, branch=args.branch)
    until_ref = f"origin/{args.branch}"
    tip_sha = git_mine.get_tip_sha(args.clone_dir, ref=until_ref)

    conn = db.connect(args.db)
    db.init_schema(conn)

    all_files = git_mine.list_tree_files(args.clone_dir, ref=tip_sha)
    pipeline.ingest_snapshot(conn, args.clone_dir, tip_sha, all_files)

    all_cve_ids = [row["cve_id"] for row in conn.execute("SELECT DISTINCT cve_id FROM exploitation_history")]
    print(f"Recomputing derived columns for {len(all_cve_ids)} CVEs with history...")
    pipeline.recompute_derived_for(conn, all_cve_ids)

    conn.close()
    print(f"Re-ingestion complete at tip {tip_sha}")


if __name__ == "__main__":
    main()
