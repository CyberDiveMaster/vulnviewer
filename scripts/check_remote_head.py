"""Cheap pre-check for GitHub Actions: compares Vulnrichment's current HEAD
commit (via a single GitHub API call, no clone/fetch needed) against our
last_processed_sha. Writes a "changed=true/false" flag to $GITHUB_OUTPUT so
the workflow can skip the expensive clone-restore/mine/export/commit steps
entirely on the many runs where nothing changed -- this is what makes
running the schedule every 10 minutes cheap rather than every run repeating
the ~300MB clone restore + fetch.
"""

import json
import os
import sys
import urllib.request
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parent))

from common import db

PROJECT_ROOT = Path(__file__).resolve().parent.parent
DEFAULT_DB_PATH = PROJECT_ROOT / "data" / "vulnviewer.db"
API_URL = "https://api.github.com/repos/cisagov/vulnrichment/commits/develop"


def get_remote_head_sha():
    req = urllib.request.Request(
        API_URL,
        headers={"User-Agent": "vulnviewer-check", "Accept": "application/vnd.github+json"},
    )
    token = os.environ.get("GITHUB_TOKEN")
    if token:
        req.add_header("Authorization", f"Bearer {token}")
    with urllib.request.urlopen(req) as resp:
        data = json.load(resp)
    return data["sha"]


def write_output(name, value):
    path = os.environ.get("GITHUB_OUTPUT")
    if not path:
        return
    with open(path, "a", encoding="utf-8") as f:
        f.write(f"{name}={value}\n")


def main():
    conn = db.connect(DEFAULT_DB_PATH)
    db.init_schema(conn)
    last_sha = db.meta_get(conn, "last_processed_sha")
    conn.close()

    remote_sha = get_remote_head_sha()
    changed = remote_sha != last_sha

    print(f"local last_processed_sha = {last_sha}")
    print(f"remote develop HEAD sha  = {remote_sha}")
    print(f"changed = {changed}")

    write_output("changed", "true" if changed else "false")


if __name__ == "__main__":
    main()
