"""SQLite schema and helpers shared by backfill_history.py, update_incremental.py
and export_json.py. Kept dependency-free (stdlib sqlite3 only)."""

import sqlite3
from pathlib import Path

SCHEMA_VERSION = "2"

_DDL = """
CREATE TABLE IF NOT EXISTS meta (
    key TEXT PRIMARY KEY,
    value TEXT
);

CREATE TABLE IF NOT EXISTS cve (
    cve_id TEXT PRIMARY KEY,
    state TEXT,
    date_reserved TEXT,
    date_published TEXT,
    date_updated TEXT,
    cvss_vector TEXT,
    cvss_score REAL,
    cvss_severity TEXT,
    cvss_version TEXT,
    cvss_source TEXT,
    exploitation TEXT,
    automatable TEXT,
    technical_impact TEXT,
    ssvc_timestamp TEXT,
    kev_date_added TEXT,
    kev_reference TEXT,
    first_none_date TEXT,
    first_poc_date TEXT,
    first_active_date TEXT,
    exploitation_left_censored INTEGER DEFAULT 0,
    days_none_to_active INTEGER,
    days_poc_to_active INTEGER,
    days_publish_to_active INTEGER,
    raw_file_path TEXT,
    last_seen_sha TEXT,
    updated_at TEXT
);

CREATE TABLE IF NOT EXISTS cve_vendor_product (
    id INTEGER PRIMARY KEY AUTOINCREMENT,
    cve_id TEXT NOT NULL,
    vendor TEXT,
    product TEXT,
    UNIQUE(cve_id, vendor, product)
);
CREATE INDEX IF NOT EXISTS idx_vp_cve ON cve_vendor_product(cve_id);

CREATE TABLE IF NOT EXISTS cve_cwe (
    id INTEGER PRIMARY KEY AUTOINCREMENT,
    cve_id TEXT NOT NULL,
    cwe_id TEXT,
    description TEXT,
    UNIQUE(cve_id, cwe_id)
);
CREATE INDEX IF NOT EXISTS idx_cwe_cve ON cve_cwe(cve_id);

CREATE TABLE IF NOT EXISTS cve_cvss (
    id INTEGER PRIMARY KEY AUTOINCREMENT,
    cve_id TEXT NOT NULL,
    source TEXT,
    version TEXT,
    vector TEXT,
    base_score REAL,
    base_severity TEXT,
    is_primary INTEGER DEFAULT 0
);
CREATE INDEX IF NOT EXISTS idx_cvss_cve ON cve_cvss(cve_id);

CREATE TABLE IF NOT EXISTS exploitation_history (
    id INTEGER PRIMARY KEY AUTOINCREMENT,
    cve_id TEXT NOT NULL,
    value TEXT NOT NULL,
    previous_value TEXT,
    observed_date TEXT NOT NULL,
    ssvc_timestamp TEXT,
    commit_sha TEXT NOT NULL,
    UNIQUE(cve_id, commit_sha)
);
CREATE INDEX IF NOT EXISTS idx_hist_cve_date ON exploitation_history(cve_id, observed_date);
"""

_CVSS_VERSION_RANK = {"4.0": 4, "3.1": 3, "3.0": 2, "2.0": 1}


def connect(db_path):
    Path(db_path).parent.mkdir(parents=True, exist_ok=True)
    conn = sqlite3.connect(db_path)
    conn.row_factory = sqlite3.Row
    conn.execute("PRAGMA foreign_keys = OFF")
    return conn


def init_schema(conn):
    conn.executescript(_DDL)
    _ensure_column(conn, "cve", "days_publish_to_active", "INTEGER")
    meta_set(conn, "schema_version", SCHEMA_VERSION)
    conn.commit()


def _ensure_column(conn, table, column, coltype):
    """CREATE TABLE IF NOT EXISTS only helps brand-new DBs; existing local
    DBs need an explicit ALTER TABLE when a column is added later."""
    existing = {row["name"] for row in conn.execute(f"PRAGMA table_info({table})")}
    if column not in existing:
        conn.execute(f"ALTER TABLE {table} ADD COLUMN {column} {coltype}")


def meta_get(conn, key, default=None):
    row = conn.execute("SELECT value FROM meta WHERE key = ?", (key,)).fetchone()
    return row["value"] if row is not None else default


def meta_set(conn, key, value):
    conn.execute(
        "INSERT INTO meta(key, value) VALUES(?, ?) "
        "ON CONFLICT(key) DO UPDATE SET value = excluded.value",
        (key, value),
    )


def upsert_cve_snapshot(conn, parsed):
    """parsed: dict from cve_parser.parse_cve_json, current-state fields only.
    Derived columns (first_*_date, days_*) are left untouched here and
    populated separately by recompute_derived()."""
    conn.execute(
        """
        INSERT INTO cve (
            cve_id, state, date_reserved, date_published, date_updated,
            exploitation, automatable, technical_impact, ssvc_timestamp,
            kev_date_added, kev_reference, raw_file_path, last_seen_sha, updated_at
        ) VALUES (
            :cve_id, :state, :date_reserved, :date_published, :date_updated,
            :exploitation, :automatable, :technical_impact, :ssvc_timestamp,
            :kev_date_added, :kev_reference, :raw_file_path, :last_seen_sha, :updated_at
        )
        ON CONFLICT(cve_id) DO UPDATE SET
            state=excluded.state,
            date_reserved=excluded.date_reserved,
            date_published=excluded.date_published,
            date_updated=excluded.date_updated,
            exploitation=excluded.exploitation,
            automatable=excluded.automatable,
            technical_impact=excluded.technical_impact,
            ssvc_timestamp=excluded.ssvc_timestamp,
            kev_date_added=excluded.kev_date_added,
            kev_reference=excluded.kev_reference,
            raw_file_path=excluded.raw_file_path,
            last_seen_sha=excluded.last_seen_sha,
            updated_at=excluded.updated_at
        """,
        parsed,
    )

    conn.execute("DELETE FROM cve_vendor_product WHERE cve_id = ?", (parsed["cve_id"],))
    for vendor, product in parsed["vendor_products"]:
        conn.execute(
            "INSERT OR IGNORE INTO cve_vendor_product(cve_id, vendor, product) VALUES (?, ?, ?)",
            (parsed["cve_id"], vendor, product),
        )

    conn.execute("DELETE FROM cve_cwe WHERE cve_id = ?", (parsed["cve_id"],))
    for cwe_id, description in parsed["cwes"]:
        conn.execute(
            "INSERT OR IGNORE INTO cve_cwe(cve_id, cwe_id, description) VALUES (?, ?, ?)",
            (parsed["cve_id"], cwe_id, description),
        )

    conn.execute("DELETE FROM cve_cvss WHERE cve_id = ?", (parsed["cve_id"],))
    primary = _pick_primary_cvss(parsed["cvss_list"])
    for entry in parsed["cvss_list"]:
        is_primary = 1 if entry is primary else 0
        conn.execute(
            """INSERT INTO cve_cvss(cve_id, source, version, vector, base_score, base_severity, is_primary)
               VALUES (?, ?, ?, ?, ?, ?, ?)""",
            (
                parsed["cve_id"], entry["source"], entry["version"], entry["vector"],
                entry["base_score"], entry["base_severity"], is_primary,
            ),
        )

    if primary is not None:
        conn.execute(
            """UPDATE cve SET cvss_vector=?, cvss_score=?, cvss_severity=?, cvss_version=?, cvss_source=?
               WHERE cve_id=?""",
            (
                primary["vector"], primary["base_score"], primary["base_severity"],
                primary["version"], primary["source"], parsed["cve_id"],
            ),
        )


def _pick_primary_cvss(cvss_list):
    if not cvss_list:
        return None

    def rank(entry):
        version_rank = _CVSS_VERSION_RANK.get(entry["version"], 0)
        source_rank = 1 if entry["source"] == "cna" else 0
        return (version_rank, source_rank)

    return max(cvss_list, key=rank)


def record_exploitation_transition(conn, cve_id, value, previous_value, observed_date, ssvc_timestamp, commit_sha):
    conn.execute(
        """INSERT OR IGNORE INTO exploitation_history
           (cve_id, value, previous_value, observed_date, ssvc_timestamp, commit_sha)
           VALUES (?, ?, ?, ?, ?, ?)""",
        (cve_id, value, previous_value, observed_date, ssvc_timestamp, commit_sha),
    )


def recompute_derived(conn, cve_id):
    """Recompute first_none_date / first_poc_date / first_active_date,
    exploitation_left_censored, and the two day-count columns for one CVE,
    from its full exploitation_history. Milestones reflect the FIRST time
    each value was observed; the full transition audit trail (including any
    later oscillations) always remains available in exploitation_history."""
    rows = conn.execute(
        """SELECT value, previous_value, observed_date FROM exploitation_history
           WHERE cve_id = ? ORDER BY observed_date ASC, id ASC""",
        (cve_id,),
    ).fetchall()

    if not rows:
        return

    first_none = next((r["observed_date"] for r in rows if r["value"] == "none"), None)
    first_poc = next((r["observed_date"] for r in rows if r["value"] == "poc"), None)
    first_active = next((r["observed_date"] for r in rows if r["value"] == "active"), None)

    left_censored = 1 if rows[0]["previous_value"] is None and rows[0]["value"] != "none" else 0

    days_none_to_active = _day_delta(first_none, first_active)
    days_poc_to_active = _day_delta(first_poc, first_active)

    cve_row = conn.execute("SELECT date_published FROM cve WHERE cve_id = ?", (cve_id,)).fetchone()
    date_published = cve_row["date_published"] if cve_row else None
    days_publish_to_active = _publish_day_delta(date_published, first_active)

    conn.execute(
        """UPDATE cve SET first_none_date=?, first_poc_date=?, first_active_date=?,
           exploitation_left_censored=?, days_none_to_active=?, days_poc_to_active=?,
           days_publish_to_active=?
           WHERE cve_id=?""",
        (first_none, first_poc, first_active, left_censored,
         days_none_to_active, days_poc_to_active, days_publish_to_active, cve_id),
    )


def _to_date(iso_str):
    from datetime import datetime
    return datetime.fromisoformat(iso_str.replace("Z", "+00:00")).date()


def _day_delta(start_iso, end_iso):
    """Whole calendar days between two ISO timestamps, ignoring time-of-day.
    None if either side is missing or start is after end (should not happen
    given these are walked in chronological order, but guards against it)."""
    if not start_iso or not end_iso:
        return None
    start, end = _to_date(start_iso), _to_date(end_iso)
    if end < start:
        return None
    return (end - start).days


def _publish_day_delta(published_iso, active_iso):
    """Whole calendar days from date_published to first_active_date. Unlike
    _day_delta, a same-day-or-earlier transition clamps to 0 rather than
    None -- e.g. a CVE assessed as "active" on the very day it was published
    should read 0, not N/A. None only when the CVE never became active."""
    if not published_iso or not active_iso:
        return None
    published, active = _to_date(published_iso), _to_date(active_iso)
    return max((active - published).days, 0)
