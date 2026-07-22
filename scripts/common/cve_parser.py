"""Parse a single Vulnrichment CVE JSON record (CVE 5.x record format) into
the flat structures used by db.py. Shared by backfill_history.py and
update_incremental.py so both jobs agree on field extraction."""

import re

_CVSS_KEYS = ("cvssV4_0", "cvssV3_1", "cvssV3_0", "cvssV2_0")
CVE_PATH_RE = re.compile(r"^\d{4}/[^/]+/CVE-\d{4}-\d+\.json$")


def parse_cve_json(data, raw_file_path=None):
    """Returns a dict with current-state fields for db.upsert_cve_snapshot(),
    plus 'vendor_products', 'cwes', 'cvss_list' sub-lists.
    Tolerant of missing containers/affected/problemTypes (e.g. REJECTED CVEs)."""
    cve_metadata = data.get("cveMetadata", {}) or {}
    cve_id = cve_metadata.get("cveId")
    containers = data.get("containers", {}) or {}
    cna = containers.get("cna", {}) or {}

    vendor_products = []
    for affected in cna.get("affected", []) or []:
        vendor = affected.get("vendor")
        product = affected.get("product")
        if vendor or product:
            vendor_products.append((vendor, product))

    cwes = _extract_cwes(cna.get("problemTypes", []) or [])

    cvss_list = []
    cvss_list.extend(_extract_cvss(cna.get("metrics", []) or [], source="cna"))

    exploitation = automatable = technical_impact = ssvc_timestamp = None
    kev_date_added = kev_reference = None

    adp_list = containers.get("adp", []) or []
    for adp in adp_list:
        # CNA-supplied problemTypes sometimes carry a CWE only as free-text
        # (description "CWE-436 ...") with no cweId field set at all -- CISA's
        # ADP entry then fills in the missing cweId on what's otherwise the
        # same description. Merge both sources, deduping by cweId, so the
        # CNA's own omission doesn't silently drop the CWE.
        for cwe_id, description in _extract_cwes(adp.get("problemTypes", []) or []):
            if cwe_id not in {c for c, _ in cwes}:
                cwes.append((cwe_id, description))
        cvss_list.extend(_extract_cvss(adp.get("metrics", []) or [], source="adp"))
        for metric in adp.get("metrics", []) or []:
            other = metric.get("other")
            if not other:
                continue
            other_type = other.get("type")
            content = other.get("content", {}) or {}
            if other_type == "ssvc":
                ssvc_timestamp = content.get("timestamp") or ssvc_timestamp
                for option in content.get("options", []) or []:
                    if "Exploitation" in option:
                        exploitation = option["Exploitation"]
                    if "Automatable" in option:
                        automatable = option["Automatable"]
                    if "Technical Impact" in option:
                        technical_impact = option["Technical Impact"]
            elif other_type == "kev":
                kev_date_added = content.get("dateAdded") or kev_date_added
                kev_reference = content.get("reference") or kev_reference

    return {
        "cve_id": cve_id,
        "state": cve_metadata.get("state"),
        "date_reserved": cve_metadata.get("dateReserved"),
        "date_published": cve_metadata.get("datePublished"),
        "date_updated": cve_metadata.get("dateUpdated"),
        "exploitation": exploitation,
        "automatable": automatable,
        "technical_impact": technical_impact,
        "ssvc_timestamp": ssvc_timestamp,
        "kev_date_added": kev_date_added,
        "kev_reference": kev_reference,
        "raw_file_path": raw_file_path,
        "last_seen_sha": None,  # filled in by caller
        "updated_at": None,  # filled in by caller
        "vendor_products": vendor_products,
        "cwes": cwes,
        "cvss_list": cvss_list,
    }


def extract_exploitation(data):
    """Cheap extraction of just the Exploitation value + ssvc timestamp,
    used by the git-history mining loop (avoids building the full parsed
    dict for every historical commit)."""
    containers = data.get("containers", {}) or {}
    for adp in containers.get("adp", []) or []:
        for metric in adp.get("metrics", []) or []:
            other = metric.get("other")
            if not other or other.get("type") != "ssvc":
                continue
            content = other.get("content", {}) or {}
            timestamp = content.get("timestamp")
            for option in content.get("options", []) or []:
                if "Exploitation" in option:
                    return option["Exploitation"], timestamp
    return None, None


def extract_cve_id(data, raw_file_path=None):
    cve_id = (data.get("cveMetadata", {}) or {}).get("cveId")
    if cve_id:
        return cve_id
    if raw_file_path:
        match = re.search(r"(CVE-\d{4}-\d+)", raw_file_path)
        if match:
            return match.group(1)
    return None


def _extract_cwes(problem_types):
    result = []
    for problem_type in problem_types:
        for desc in problem_type.get("descriptions", []) or []:
            cwe_id = desc.get("cweId")
            if cwe_id:
                result.append((cwe_id, desc.get("description")))
    return result


def _extract_cvss(metrics, source):
    result = []
    for metric in metrics:
        for key in _CVSS_KEYS:
            block = metric.get(key)
            if not block:
                continue
            result.append({
                "source": source,
                "version": block.get("version"),
                "vector": block.get("vectorString"),
                "base_score": block.get("baseScore"),
                "base_severity": block.get("baseSeverity"),
            })
    return result
