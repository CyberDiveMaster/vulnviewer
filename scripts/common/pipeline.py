"""Shared mining/ingestion logic used by both backfill_history.py (full
history, unbounded) and update_incremental.py (bounded commit range).
Keeping this in one place means both jobs agree on how a commit range is
walked and how a CVE snapshot is ingested."""

import json
from datetime import datetime, timezone

from . import db, git_mine
from .cve_parser import extract_cve_id, extract_exploitation, parse_cve_json

COMMIT_CHECKPOINT_INTERVAL = 500
SNAPSHOT_CHECKPOINT_INTERVAL = 1000


def now_iso():
    return datetime.now(timezone.utc).isoformat()


def load_last_values(conn):
    rows = conn.execute(
        """
        SELECT eh.cve_id, eh.value FROM exploitation_history eh
        INNER JOIN (
            SELECT cve_id, MAX(observed_date) AS max_date FROM exploitation_history GROUP BY cve_id
        ) latest ON latest.cve_id = eh.cve_id AND latest.max_date = eh.observed_date
        """
    ).fetchall()
    return {row["cve_id"]: row["value"] for row in rows}


def mine_exploitation_history(conn, repo_dir, until_ref, resume_from_sha):
    """Walks commits in (resume_from_sha, until_ref] whose diff touches an
    Exploitation-related line, recording a transition row whenever a CVE's
    Exploitation value actually changes (structural JSON comparison, not
    text diff). Returns the set of cve_ids touched, so callers can scope
    recompute_derived() to just those CVEs."""
    print(f"Listing Exploitation-relevant commits since={resume_from_sha or '(start)'} ...")
    commits = git_mine.list_exploitation_commits(repo_dir, until_ref=until_ref, since_sha=resume_from_sha)
    print(f"{len(commits)} candidate commits to walk.")

    last_value = load_last_values(conn)
    touched_cve_ids = set()

    with git_mine.CatFileBatch(repo_dir) as cat:
        for i, (sha, commit_date, paths) in enumerate(commits, start=1):
            for path in paths:
                blob = cat.get(sha, path)
                if blob is None:
                    continue
                try:
                    data = json.loads(blob)
                except json.JSONDecodeError:
                    continue
                cve_id = extract_cve_id(data, raw_file_path=path)
                if not cve_id:
                    continue
                value, ssvc_timestamp = extract_exploitation(data)
                if value is None:
                    continue
                previous = last_value.get(cve_id)
                if value != previous:
                    db.record_exploitation_transition(
                        conn, cve_id, value, previous, commit_date, ssvc_timestamp, sha
                    )
                    last_value[cve_id] = value
                    touched_cve_ids.add(cve_id)

            if i % COMMIT_CHECKPOINT_INTERVAL == 0:
                db.meta_set(conn, "last_processed_sha", sha)
                conn.commit()
                print(f"  ...{i}/{len(commits)} commits processed")

    conn.commit()
    print(f"Exploitation history mining complete ({len(touched_cve_ids)} CVEs touched).")
    return touched_cve_ids


def ingest_snapshot(conn, repo_dir, ref, files):
    """Parses and upserts the current-state row for each given file path,
    as it exists at `ref` (a sha or ref name). Returns the set of cve_ids
    successfully ingested."""
    print(f"Ingesting current snapshot for {len(files)} CVE files at {ref}...")
    timestamp = now_iso()
    ingested = set()

    with git_mine.CatFileBatch(repo_dir) as cat:
        for i, path in enumerate(files, start=1):
            blob = cat.get(ref, path)
            if blob is None:
                continue
            try:
                data = json.loads(blob)
            except json.JSONDecodeError:
                continue
            parsed = parse_cve_json(data, raw_file_path=path)
            if not parsed["cve_id"]:
                continue
            parsed["last_seen_sha"] = ref
            parsed["updated_at"] = timestamp
            db.upsert_cve_snapshot(conn, parsed)
            ingested.add(parsed["cve_id"])

            if i % SNAPSHOT_CHECKPOINT_INTERVAL == 0:
                conn.commit()
                print(f"  ...{i}/{len(files)} CVE files ingested")

    conn.commit()
    print(f"Snapshot ingestion complete ({len(ingested)} CVEs).")
    return ingested


def recompute_derived_for(conn, cve_ids):
    for cve_id in cve_ids:
        db.recompute_derived(conn, cve_id)
    conn.commit()
