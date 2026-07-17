"""Flattens data/vulnviewer.db into docs/data/cves.json for the static
frontend. No joins needed client-side -- everything is pre-flattened here."""

import argparse
import gzip
import json
import sys
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parent))

from common import db, pipeline

PROJECT_ROOT = Path(__file__).resolve().parent.parent
DEFAULT_DB_PATH = PROJECT_ROOT / "data" / "vulnviewer.db"
# Committed to git and served by GitHub Pages. Gzip-compressed because the
# raw JSON is ~150MB for the full Vulnrichment dataset (162k+ CVEs), well
# over GitHub's 100MB per-file push limit; compressed it's ~10MB. The
# frontend (docs/js/app.js) decompresses it client-side via
# DecompressionStream('gzip') before parsing.
DEFAULT_OUTPUT_PATH = PROJECT_ROOT / "docs" / "data" / "cves.json.gz"


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
    parser.add_argument("--output", type=Path, default=DEFAULT_OUTPUT_PATH)
    args = parser.parse_args()

    conn = db.connect(args.db)
    rows = build_rows(conn)
    conn.close()

    args.output.parent.mkdir(parents=True, exist_ok=True)
    payload = {
        "generated_at": pipeline.now_iso(),
        "cve_count": len(rows),
        "rows": rows,
    }
    encoded = json.dumps(payload, ensure_ascii=False, separators=(",", ":")).encode("utf-8")
    with gzip.open(args.output, "wb", compresslevel=9) as f:
        f.write(encoded)

    print(
        f"Exported {len(rows)} CVEs to {args.output} "
        f"({len(encoded) / 1024 / 1024:.1f}MB -> {args.output.stat().st_size / 1024 / 1024:.1f}MB gzipped)"
    )


if __name__ == "__main__":
    main()
