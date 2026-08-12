"""Flattens data/vulnviewer.db into docs/data/cves-*.jsonl shards for the
static frontend. No joins needed client-side -- everything is pre-flattened
here.

Deliberately NOT gzip-compressed and NOT a single JSON array: one CVE object
per line (JSON Lines) within each shard, so that when only a handful of
CVEs change between runs, git's own delta compression stores just those
changed lines instead of an entirely new blob every time (a pre-compressed
file's bytes change almost completely for any 1-row edit, defeating delta
compression). GitHub Pages' CDN gzips the response over the wire on its own
(confirmed via response headers), so this costs nothing on the transfer
side. generated_at/cve_count live in a separate tiny meta.json specifically
because they change on every run -- keeping them out of the shards means a
truly no-op re-export produces byte-identical files.

Sharded (not one file) for two reasons: (1) GitHub hard-blocks any single
committed file over 100MB, and the full dataset is already well past that
uncompressed; (2) each CVE is assigned to a shard by a stable hash of its
own cve_id (NOT by row position), so adding/removing/reordering OTHER CVEs
never shifts which shard an unrelated CVE lives in or its byte offset
within that shard -- only the shard(s) actually containing a changed CVE
differ from the previous run."""

import argparse
import hashlib
import json
import sys
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parent))

from common import db, pipeline

PROJECT_ROOT = Path(__file__).resolve().parent.parent
DEFAULT_DB_PATH = PROJECT_ROOT / "data" / "vulnviewer.db"
DEFAULT_OUTPUT_DIR = PROJECT_ROOT / "docs" / "data"
DEFAULT_META_PATH = PROJECT_ROOT / "docs" / "data" / "meta.json"
# ~176MB uncompressed today; sized so each shard has plenty of headroom
# below GitHub's 100MB hard limit as the dataset keeps growing. Bumping this
# later is a one-time full reshuffle (every shard's membership changes), so
# it's picked generously rather than tightly.
NUM_SHARDS = 12


def shard_for(cve_id):
    return int(hashlib.sha1(cve_id.encode("utf-8")).hexdigest(), 16) % NUM_SHARDS


def build_grouped_maps(conn):
    vendor_product_map = {}
    for row in conn.execute("SELECT cve_id, vendor, product FROM cve_vendor_product"):
        vendor_product_map.setdefault(row["cve_id"], []).append((row["vendor"], row["product"]))

    cwe_map = {}
    for row in conn.execute("SELECT cve_id, cwe_id, description FROM cve_cwe"):
        cwe_map.setdefault(row["cve_id"], []).append((row["cwe_id"], row["description"]))

    cvss_map = {}
    for row in conn.execute(
        "SELECT cve_id, source, version, vector, base_score, base_severity FROM cve_cvss"
    ):
        cvss_map.setdefault(row["cve_id"], []).append({
            "source": row["source"],
            "version": row["version"],
            "vector": row["vector"],
            "base_score": row["base_score"],
            "base_severity": row["base_severity"],
        })

    return vendor_product_map, cwe_map, cvss_map


def build_rows(conn):
    vendor_product_map, cwe_map, cvss_map = build_grouped_maps(conn)
    rows = []

    for cve in conn.execute("SELECT * FROM cve ORDER BY cve_id"):
        cve_id = cve["cve_id"]
        vendor_products = vendor_product_map.get(cve_id, [])
        cwes = cwe_map.get(cve_id, [])

        vendors = [v for v, _ in vendor_products if v]
        products = [p for _, p in vendor_products if p]

        rows.append({
            "cve_id": cve_id,
            "state": cve["state"],
            "date_reserved": cve["date_reserved"],
            "date_published": cve["date_published"],
            "date_updated": cve["date_updated"],
            "cvss_vector": cve["cvss_vector"],
            "cvss_score": cve["cvss_score"],
            "cvss_severity": cve["cvss_severity"],
            "cvss_version": cve["cvss_version"],
            "cvss_source": cve["cvss_source"],
            "cvss_all": cvss_map.get(cve_id, []),
            "exploitation": cve["exploitation"],
            "automatable": cve["automatable"],
            "technical_impact": cve["technical_impact"],
            "vendor": "; ".join(dict.fromkeys(vendors)),
            "product": "; ".join(dict.fromkeys(products)),
            "vendor_product": [f"{v}/{p}" for v, p in vendor_products],
            "cwe": "; ".join(cwe_id for cwe_id, _ in cwes),
            "cwe_ids": [cwe_id for cwe_id, _ in cwes],
            "kev_date_added": cve["kev_date_added"],
            "kev_reference": cve["kev_reference"],
            "first_none_date": cve["first_none_date"],
            "first_poc_date": cve["first_poc_date"],
            "first_active_date": cve["first_active_date"],
            "exploitation_left_censored": bool(cve["exploitation_left_censored"]),
            "days_none_to_active": cve["days_none_to_active"],
            "days_poc_to_active": cve["days_poc_to_active"],
            "days_publish_to_active": cve["days_publish_to_active"],
            "raw_file_path": cve["raw_file_path"],
        })

    return rows


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--db", type=Path, default=DEFAULT_DB_PATH)
    parser.add_argument("--output-dir", type=Path, default=DEFAULT_OUTPUT_DIR)
    parser.add_argument("--meta-output", type=Path, default=DEFAULT_META_PATH)
    args = parser.parse_args()

    conn = db.connect(args.db)
    rows = build_rows(conn)
    conn.close()

    args.output_dir.mkdir(parents=True, exist_ok=True)
    shards = [[] for _ in range(NUM_SHARDS)]
    for row in rows:
        shards[shard_for(row["cve_id"])].append(row)

    total_bytes = 0
    for i, shard_rows in enumerate(shards):
        # Stable order within the shard too, so an unrelated CVE landing in
        # the same shard doesn't shuffle this shard's own byte layout.
        shard_rows.sort(key=lambda r: r["cve_id"])
        path = args.output_dir / f"cves-{i}.jsonl"
        with open(path, "w", encoding="utf-8", newline="\n") as f:
            for row in shard_rows:
                f.write(json.dumps(row, ensure_ascii=False, separators=(",", ":")))
                f.write("\n")
        total_bytes += path.stat().st_size

    args.meta_output.write_text(
        json.dumps(
            {"generated_at": pipeline.now_iso(), "cve_count": len(rows), "shard_count": NUM_SHARDS},
            ensure_ascii=False,
        ),
        encoding="utf-8",
    )

    print(
        f"Exported {len(rows)} CVEs across {NUM_SHARDS} shards to {args.output_dir} "
        f"({total_bytes / 1024 / 1024:.1f}MB total)"
    )


if __name__ == "__main__":
    main()
