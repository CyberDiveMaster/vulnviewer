const NONE_SENTINEL = "__none__";

const HTML_ESCAPES = { "&": "&amp;", "<": "&lt;", ">": "&gt;", '"': "&quot;", "'": "&#39;" };

// Formatters below build HTML strings that Tabulator inserts directly into
// the cell, so any value coming from the (externally-sourced) Vulnrichment
// data must be escaped here rather than trusted as-is.
function escapeHtml(str) {
  return String(str).replace(/[&<>"']/g, (c) => HTML_ESCAPES[c]);
}

function naFormatter(cell) {
  const v = cell.getValue();
  if (v === null || v === undefined || v === "") {
    return '<span class="na-cell">N/A</span>';
  }
  return escapeHtml(v);
}

// A handful of Vendor/Product values are pathologically long (e.g. one CVE
// lists 100+ individual product model numbers, 130k+ characters joined
// together) which would otherwise force that column absurdly wide under
// fitDataStretch sizing. Truncate for display; the full value is still
// available via the tooltip and in CSV exports.
function truncateFormatter(maxLen) {
  return function (cell) {
    const v = cell.getValue();
    if (v === null || v === undefined || v === "") {
      return '<span class="na-cell">N/A</span>';
    }
    const str = String(v);
    return str.length <= maxLen ? escapeHtml(str) : escapeHtml(str.slice(0, maxLen)) + "…";
  };
}

function fullValueTooltip(e, cell) {
  return cell.getValue() || "";
}

// Links each CWE-NNN to its MITRE definitions page. Capped at a handful of
// links per cell -- most CVEs list one or two CWEs, but a few list dozens,
// and rendering every one as a full <a> tag would blow out the column width
// the same way uncapped Vendor/Product lists would (see truncateFormatter
// above). The full list is still available via the tooltip.
function cweFormatter(cell) {
  const ids = cell.getRow().getData().cwe_ids || [];
  if (ids.length === 0) return '<span class="na-cell">N/A</span>';

  const MAX_LINKS = 6;
  const links = ids.slice(0, MAX_LINKS).map((id) => {
    const match = /^CWE-(\d+)$/i.exec(id);
    if (!match) return escapeHtml(id);
    const href = `https://cwe.mitre.org/data/definitions/${match[1]}.html`;
    return `<a href="${href}" target="_blank" rel="noopener">${escapeHtml(id)}</a>`;
  });

  let html = links.join(", ");
  if (ids.length > MAX_LINKS) {
    html += `, <span class="na-cell">+${ids.length - MAX_LINKS} more</span>`;
  }
  return html;
}

function withVersionHint(cell, formattedValue) {
  const version = cell.getRow().getData().cvss_version;
  return version ? `${formattedValue} <span class="cvss-version-hint">v${escapeHtml(version)}</span>` : formattedValue;
}

function cvssScoreFormatter(cell) {
  const v = cell.getValue();
  if (v === null || v === undefined || v === "") {
    return '<span class="na-cell">N/A</span>';
  }
  return withVersionHint(cell, escapeHtml(v));
}

// Strips the sub-second fraction from an ISO timestamp (e.g.
// "2023-08-29T19:38:55.399Z" -> "2023-08-29T19:38:55Z") -- the millisecond
// precision comes straight from Vulnrichment's own timestamps and just adds
// visual clutter here; the trailing Z/offset (UTC) is kept.
function trimMillis(isoString) {
  return String(isoString).replace(/\.\d+(Z|[+-]\d{2}:?\d{2})$/, "$1");
}

function dateFormatter(cell) {
  const v = cell.getValue();
  if (v === null || v === undefined || v === "") {
    return '<span class="na-cell">N/A</span>';
  }
  return trimMillis(v);
}

// first_active_date is a historical milestone (first time Exploitation was
// EVER observed as "active") and stays set even if a later re-assessment
// walks the value back down to "poc"/"none" -- CISA does sometimes revise
// an active call. Only display it while the CVE's CURRENT status is still
// "active"; the underlying data/CSV export still carries the true
// historical date for anyone who wants it.
function activeSinceFormatter(cell) {
  const row = cell.getRow().getData();
  if (row.exploitation !== "active") {
    return '<span class="na-cell">N/A</span>';
  }
  return dateFormatter(cell);
}

// Sorting by the raw first_active_date would place currently-inactive rows
// (displayed as N/A) in the middle of the sorted list, using a date value
// the user can no longer see -- confusing. Treat those rows as "empty" too,
// and pin them to the end regardless of asc/desc, mirroring Tabulator's own
// alignEmptyValues:"bottom" convention (see the built-in string/number
// sorters, which flip only when dir === "asc" for a "bottom" alignment).
function activeSinceSorter(a, b, aRow, bRow, column, dir) {
  const aEmpty = aRow.getData().exploitation !== "active" || !a;
  const bEmpty = bRow.getData().exploitation !== "active" || !b;
  let emptyAlign = 0;

  if (aEmpty) {
    emptyAlign = bEmpty ? 0 : -1;
  } else if (bEmpty) {
    emptyAlign = 1;
  } else {
    return a < b ? -1 : a > b ? 1 : 0;
  }

  if (dir === "asc") {
    emptyAlign *= -1;
  }
  return emptyAlign;
}

function exploitationFormatter(cell) {
  const v = cell.getValue();
  if (v === null || v === undefined || v === "") {
    return '<span class="na-cell">N/A</span>';
  }
  const text = escapeHtml(v);
  if (v !== "active") return text;
  // Built directly from the CVE ID rather than trusting Vulnrichment's own
  // kev_reference field -- that field only gets populated once Vulnrichment
  // cross-references the KEV catalog itself, which can lag behind (a CVE
  // can be genuinely KEV-listed for days before Vulnrichment reflects it).
  // CISA's catalog page takes the CVE ID as a query filter directly, so this
  // link is accurate at click-time regardless of Vulnrichment's own lag.
  const cveId = cell.getRow().getData().cve_id;
  const kevUrl = `https://www.cisa.gov/known-exploited-vulnerabilities-catalog?field_cve=${encodeURIComponent(cveId)}`;
  return `${text} <a href="${kevUrl}" target="_blank" rel="noopener" ` +
    `class="vulnrichment-link" title="Check CISA KEV catalog for this CVE">&#x1F6A8;</a>`;
}

function cveLinkFormatter(cell) {
  const v = cell.getValue();
  if (!v) return "";
  const cveOrgLink =
    `<a href="https://www.cve.org/CVERecord?id=${encodeURIComponent(v)}" target="_blank" rel="noopener">${escapeHtml(v)}</a>`;

  // raw_file_path (e.g. "2026/46xxx/CVE-2026-46817.json") comes from our
  // own ingestion, following the fixed CVE_PATH_RE shape, not arbitrary
  // external text -- safe to splice into a URL path without encoding.
  const rawPath = cell.getRow().getData().raw_file_path;
  if (!rawPath) return cveOrgLink;
  const vulnrichmentUrl = `https://github.com/cisagov/vulnrichment/blob/develop/${rawPath}`;
  return `${cveOrgLink} <a href="${vulnrichmentUrl}" target="_blank" rel="noopener" ` +
    `class="vulnrichment-link" title="View raw Vulnrichment JSON">📄</a>`;
}

// All multiselect panels across every column share this registry so that
// opening one can close the others -- each column's own click handler
// stops propagation (see below), so without this a document-level "click
// outside" listener registered per-column would never see clicks on a
// DIFFERENT column's trigger and would leave its own panel stuck open.
const multiSelectPanels = [];

document.addEventListener("click", (e) => {
  for (const { container, panel } of multiSelectPanels) {
    if (!container.contains(e.target)) panel.hidden = true;
  }
});

// Option labels are static strings we write ourselves (not external data),
// so they may contain simple markup (e.g. a faint version hint span) --
// rendered via innerHTML in the panel. The trigger button's summary text
// must stay plain, so it strips any markup back out here.
function stripHtml(html) {
  const tmp = document.createElement("div");
  tmp.innerHTML = html;
  return tmp.textContent;
}

// Checkbox-dropdown multi-select header filter (e.g. "everything except
// active" = check poc + none + (No assessment)). Native <select multiple>
// would technically work but requires a non-obvious ctrl/cmd-click gesture
// to pick more than one option, so this builds a small custom popup instead.
function multiSelectHeaderFilter(valuesMap) {
  const options = { [NONE_SENTINEL]: "(No assessment)", ...valuesMap };

  return function (cell, onRendered, success) {
    const container = document.createElement("span");
    container.classList.add("multiselect-filter");

    const trigger = document.createElement("button");
    trigger.type = "button";
    trigger.classList.add("multiselect-trigger");
    trigger.textContent = "(All)";

    const panel = document.createElement("div");
    panel.classList.add("multiselect-panel");
    panel.hidden = true;
    multiSelectPanels.push({ container, panel });

    const selected = new Set();

    function refreshTrigger() {
      if (selected.size === 0) {
        trigger.textContent = "(All)";
        return;
      }
      const labels = Object.entries(options)
        .filter(([value]) => selected.has(value))
        .map(([, label]) => stripHtml(label));
      trigger.textContent = labels.join(", ");
      trigger.title = labels.join(", ");
    }

    for (const [value, label] of Object.entries(options)) {
      const row = document.createElement("label");
      row.classList.add("multiselect-option");
      const checkbox = document.createElement("input");
      checkbox.type = "checkbox";
      checkbox.value = value;
      checkbox.addEventListener("change", () => {
        if (checkbox.checked) {
          selected.add(value);
        } else {
          selected.delete(value);
        }
        refreshTrigger();
        success(selected.size ? Array.from(selected) : "");
      });
      const labelSpan = document.createElement("span");
      labelSpan.innerHTML = " " + label;
      row.appendChild(checkbox);
      row.appendChild(labelSpan);
      panel.appendChild(row);
    }

    trigger.addEventListener("click", (e) => {
      e.stopPropagation();
      const opening = panel.hidden;

      // Close every other column's panel -- stopPropagation above means
      // the shared document click listener never sees this click, so each
      // trigger has to close its siblings itself.
      for (const other of multiSelectPanels) {
        if (other.panel !== panel) other.panel.hidden = true;
      }

      if (opening) {
        // .multiselect-panel is "position: fixed", but Tabulator applies
        // its own CSS transform to the root .tabulator element (a no-op
        // identity matrix, but a transform nonetheless) -- per spec, ANY
        // transform value on an ancestor makes IT the containing block for
        // fixed-position descendants instead of the viewport. So position
        // relative to that element's rect, not the raw viewport-relative
        // getBoundingClientRect() values.
        const tableRect = document.querySelector(".tabulator").getBoundingClientRect();
        const rect = trigger.getBoundingClientRect();
        panel.style.top = `${rect.bottom - tableRect.top}px`;
        panel.style.left = `${rect.left - tableRect.left}px`;
      }
      panel.hidden = !opening;
    });

    container.appendChild(trigger);
    container.appendChild(panel);
    return container;
  };
}

function multiSelectFilterFunc(headerValue, rowValue) {
  if (!headerValue || headerValue.length === 0) return true;
  const normalized = rowValue === null || rowValue === undefined || rowValue === "" ? NONE_SENTINEL : rowValue;
  return headerValue.includes(normalized);
}

function multiSelectEmptyCheck(value) {
  return !value || value.length === 0;
}

// Pipe-delimited OR substring match, e.g. "forti|palo|sonic" matches any
// row whose value contains at least one of the segments (case-insensitive,
// each segment still a partial/substring match -- same as Tabulator's own
// default "like" behavior, just OR'd across multiple terms).
function pipeOrFilterFunc(headerValue, rowValue) {
  if (!headerValue) return true;
  const needles = String(headerValue).split("|").map((s) => s.trim().toLowerCase()).filter(Boolean);
  if (needles.length === 0) return true;
  const haystack = String(rowValue || "").toLowerCase();
  return needles.some((n) => haystack.includes(n));
}

function minScoreFilterFunc(headerValue, rowValue) {
  if (headerValue === "" || headerValue === null || headerValue === undefined) return true;
  const min = Number(headerValue);
  if (Number.isNaN(min)) return true;
  return rowValue !== null && rowValue !== undefined && Number(rowValue) >= min;
}

// --- Date range header filter, shared by Date Published / Active Since ---
// A single readonly text input backed by a Flatpickr range-mode calendar --
// click a start day then an end day, no typing. Flatpickr's own UI text is
// always English regardless of the browser's language, unlike a native
// <input type="date"> (which renders its calendar/format using the
// BROWSER's UI language -- e.g. a Japanese-language browser shows "年/月/日"
// regardless of this page's lang="en", and that isn't overridable).

function formatDateLocal(date) {
  const y = date.getFullYear();
  const m = String(date.getMonth() + 1).padStart(2, "0");
  const d = String(date.getDate()).padStart(2, "0");
  return `${y}-${m}-${d}`;
}

function dateRangeHeaderFilter(cell, onRendered, success) {
  const container = document.createElement("span");
  container.classList.add("range-filter");

  const input = document.createElement("input");
  input.type = "text";
  input.readOnly = true;
  input.placeholder = "Select range...";

  const clearBtn = document.createElement("button");
  clearBtn.type = "button";
  clearBtn.textContent = "×";
  clearBtn.title = "Clear";
  clearBtn.classList.add("range-clear");

  container.appendChild(input);
  container.appendChild(clearBtn);

  // Flatpickr needs the input attached to the DOM (for positioning its
  // popup), which onRendered guarantees -- the filter function above only
  // builds detached elements.
  onRendered(() => {
    const fp = flatpickr(input, {
      mode: "range",
      dateFormat: "Y-m-d",
      onClose: (selectedDates) => {
        const [from, to] = selectedDates;
        success({
          from: from ? formatDateLocal(from) : "",
          to: to ? formatDateLocal(to) : "",
        });
      },
    });
    clearBtn.addEventListener("click", () => {
      fp.clear();
      success({ from: "", to: "" });
    });
  });

  return container;
}

function dateRangeFilterFunc(headerValue, rowValue) {
  if (!headerValue || (!headerValue.from && !headerValue.to)) return true;
  if (!rowValue) return false;
  const rowDate = String(rowValue).slice(0, 10);
  if (headerValue.from && rowDate < headerValue.from) return false;
  if (headerValue.to && rowDate > headerValue.to) return false;
  return true;
}

// Active Since displays N/A for any CVE that isn't CURRENTLY active (see
// activeSinceFormatter/activeSinceSorter above) even though the underlying
// first_active_date is still the true historical value. Filtering by that
// hidden value would let currently-inactive rows show up inside a date
// range the user can't actually see them in, so a range filter here should
// only match rows that are still displaying a real date.
function activeSinceFilterFunc(headerValue, rowValue, rowData) {
  if (!headerValue || (!headerValue.from && !headerValue.to)) return true;
  if (rowData.exploitation !== "active") return false;
  return dateRangeFilterFunc(headerValue, rowValue);
}

function dateRangeEmptyCheck(value) {
  return !value || (!value.from && !value.to);
}

const CVSS_VERSION_TOOLTIP =
  "Shows the highest CVSS version available for that CVE (v4.0 > v3.1 > v3.0 > v2.0). " +
  "When both are provided at the same version, the CNA (reporting vendor) value is used over ADP (CISA).";

function bodTierTooltip(exposed) {
  return `CISA BOD 26-04 remediation timeline (Appendix A, Table 1) assuming Publicly Exposed = ${exposed ? "Yes" : "No"}, ` +
    "computed from In KEV / Automatable / Technical Impact (from Vulnrichment). " +
    "N/A means Automatable or Technical Impact hasn't been assessed yet.";
}

// --- CVSS vector component parsing (AV/AC/PR/UI), computed client-side ---
// Value vocabularies are fixed by the CVSS spec (v3.x and v4.0 both use
// AV/AC/PR; UI's value set differs -- v3 uses N/R, v4 adds P/A -- so the
// select for UI covers the union of both).

const VECTOR_SELECT_VALUES = {
  AV: { N: "N (Network)", A: "A (Adjacent)", L: "L (Local)", P: "P (Physical)" },
  AC: { L: "L (Low)", H: "H (High)" },
  // AT (Attack Requirements) is a CVSS v4.0-only metric -- v3.x vectors
  // have no AT component at all, so it's N/A (not just absent) for any CVE
  // whose primary vector is v3.x or earlier.
  AT: {
    N: 'N (None) <span class="cvss-version-hint">v4.0</span>',
    P: 'P (Present) <span class="cvss-version-hint">v4.0</span>',
  },
  PR: { N: "N (None)", L: "L (Low)", H: "H (High)" },
  // R only exists in CVSS v3.x; P/A only exist in v4.0 -- N is the only
  // value common to both, so it's the only one left without a version hint.
  UI: {
    N: "N (None)",
    R: 'R (Required) <span class="cvss-version-hint">v3.x</span>',
    P: 'P (Passive) <span class="cvss-version-hint">v4.0</span>',
    A: 'A (Active) <span class="cvss-version-hint">v4.0</span>',
  },
};

// CISA BOD 26-04 (Prioritizing Security Updates Based on Risk, June 2026),
// Appendix A Table 1 -- reproduced verbatim from the directive's own table
// image (16 combinations of 4 binary variables -> 5 remediation tiers).
// Key is "exposed,kev,automatable,total" using 1/0; see BOD_TIER_ORDER
// below for the human-readable tier strings this maps into.
const BOD_MATRIX = {
  "1,1,1,1": "3 days & forensic triage",
  "1,1,1,0": "3 days",
  "1,1,0,1": "3 days & forensic triage",
  "1,1,0,0": "14 days",
  "1,0,1,1": "3 days",
  "1,0,1,0": "14 days",
  "1,0,0,1": "14 days",
  "1,0,0,0": "60 days",
  "0,1,1,1": "3 days & forensic triage",
  "0,1,1,0": "14 days",
  "0,1,0,1": "14 days",
  "0,1,0,0": "14 days",
  "0,0,1,1": "60 days",
  "0,0,1,0": "60 days",
  "0,0,0,1": "Fix on system upgrade",
  "0,0,0,0": "Fix on system upgrade",
};

// Most to least urgent -- used both for the CSS class lookup and to give
// the header filter's checkboxes a sensible fixed order.
const BOD_TIER_ORDER = [
  "3 days & forensic triage",
  "3 days",
  "14 days",
  "60 days",
  "Fix on system upgrade",
];

// Publicly Exposed is asset-level (per the directive, answered via CISA's
// CDM/Cyber Hygiene programs), not something Vulnrichment's CVE-level data
// can ever supply. Rather than a runtime toggle (which would need to
// mutate and re-sort/re-filter/re-render all ~178k rows on every click --
// benchmarked at ~1s via replaceData, and outright hung via updateData),
// both possible answers are computed once at load time as two separate
// static columns (see bod_tier_exposed/bod_tier_not_exposed below). In
// KEV, Automatable, and Technical Impact all come directly from
// Vulnrichment (the directive explicitly defines them that way in
// Appendix A note j).
function bodTierFor(row, assumeExposed) {
  if (row.automatable !== "yes" && row.automatable !== "no") return null;
  if (row.technical_impact !== "total" && row.technical_impact !== "partial") return null;
  const key = [
    assumeExposed ? "1" : "0",
    row.kev_date_added ? "1" : "0",
    row.automatable === "yes" ? "1" : "0",
    row.technical_impact === "total" ? "1" : "0",
  ].join(",");
  return BOD_MATRIX[key];
}

function bodTierFormatter(cell) {
  const v = cell.getValue();
  if (!v) return '<span class="na-cell">N/A</span>';
  const tierIndex = BOD_TIER_ORDER.indexOf(v);
  return `<span class="bod-tier bod-t${tierIndex + 1}">${escapeHtml(v)}</span>`;
}

const BOD_DIRECTIVE_URL = "https://www.cisa.gov/news-events/directives/bod-26-04-prioritizing-security-updates-based-risk";

// Only the "BOD 26-04" part of the title links to the official directive
// -- the "(Exposed)"/"(Not Exposed)" suffix is plain text, rendered
// smaller/dimmer so the full title fits without wrapping or clipping.
// stopPropagation on the link's click keeps following it from also
// triggering Tabulator's click-to-sort behavior on the rest of the header.
function bodTitleFormatter(cell) {
  const fullTitle = cell.getValue();
  const match = /^(.*?)\s*(\(.*\))$/.exec(fullTitle);
  const main = match ? match[1] : fullTitle;
  const suffix = match ? match[2] : "";

  const container = document.createElement("span");

  const link = document.createElement("a");
  link.href = BOD_DIRECTIVE_URL;
  link.target = "_blank";
  link.rel = "noopener";
  link.title = "View the official BOD 26-04 directive on cisa.gov";
  link.addEventListener("click", (e) => e.stopPropagation());
  link.textContent = main;
  container.appendChild(link);

  if (suffix) {
    container.appendChild(document.createTextNode(" "));
    const suffixEl = document.createElement("span");
    suffixEl.classList.add("bod-title-suffix");
    suffixEl.textContent = suffix;
    container.appendChild(suffixEl);
  }
  return container;
}

// Same "always pin empty to the bottom regardless of sort direction"
// convention as activeSinceSorter -- rows with no SSVC assessment yet have
// no meaningful urgency ranking at all, not just a low one.
function bodTierSorter(a, b, aRow, bRow, column, dir) {
  const aEmpty = !a;
  const bEmpty = !b;
  let emptyAlign = 0;
  if (aEmpty) {
    emptyAlign = bEmpty ? 0 : -1;
  } else if (bEmpty) {
    emptyAlign = 1;
  } else {
    return BOD_TIER_ORDER.indexOf(a) - BOD_TIER_ORDER.indexOf(b);
  }
  if (dir === "asc") { emptyAlign *= -1; }
  return emptyAlign;
}

function parseVectorComponents(vector) {
  const result = {};
  if (!vector) return result;
  for (const part of vector.split("/")) {
    const idx = part.indexOf(":");
    if (idx === -1) continue;
    result[part.slice(0, idx)] = part.slice(idx + 1);
  }
  return result;
}

const columns = [
  { title: "CVE ID", field: "cve_id", headerFilter: "input", formatter: cveLinkFormatter, frozen: true },
  {
    title: "Date Published", field: "date_published", sorter: "string",
    sorterParams: { alignEmptyValues: "bottom" },
    headerFilter: dateRangeHeaderFilter, headerFilterFunc: dateRangeFilterFunc,
    headerFilterEmptyCheck: dateRangeEmptyCheck, headerFilterLiveFilter: false,
    formatter: dateFormatter,
  },
  {
    title: "Active Since", field: "first_active_date", sorter: activeSinceSorter,
    headerFilter: dateRangeHeaderFilter, headerFilterFunc: activeSinceFilterFunc,
    headerFilterEmptyCheck: dateRangeEmptyCheck, headerFilterLiveFilter: false,
    formatter: activeSinceFormatter,
  },
  {
    title: "Days", field: "days_publish_to_active", sorter: "number",
    sorterParams: { alignEmptyValues: "bottom" },
    formatter: naFormatter,
  },
  {
    // width matches Technical Impact below (its own natural content width)
    // so the three SSVC decision-point columns read as a visually
    // consistent group rather than each auto-sizing to its own text.
    title: "Exploitation", field: "exploitation", width: 141,
    sorter: "string", sorterParams: { alignEmptyValues: "bottom" },
    headerFilter: multiSelectHeaderFilter({ none: "none", poc: "poc", active: "active" }),
    headerFilterFunc: multiSelectFilterFunc, headerFilterEmptyCheck: multiSelectEmptyCheck,
    formatter: exploitationFormatter,
  },
  {
    title: "Automatable", field: "automatable", width: 141,
    sorter: "string", sorterParams: { alignEmptyValues: "bottom" },
    headerFilter: multiSelectHeaderFilter({ yes: "yes", no: "no" }),
    headerFilterFunc: multiSelectFilterFunc, headerFilterEmptyCheck: multiSelectEmptyCheck,
    formatter: naFormatter,
  },
  {
    title: "Technical Impact", field: "technical_impact", width: 141,
    sorter: "string", sorterParams: { alignEmptyValues: "bottom" },
    headerFilter: multiSelectHeaderFilter({ partial: "partial", total: "total" }),
    headerFilterFunc: multiSelectFilterFunc, headerFilterEmptyCheck: multiSelectEmptyCheck,
    formatter: naFormatter,
  },
  {
    title: "CVSS Score", field: "cvss_score", sorter: "number",
    sorterParams: { alignEmptyValues: "bottom" },
    headerFilter: "input", headerFilterFunc: minScoreFilterFunc,
    headerFilterPlaceholder: "Min score", formatter: cvssScoreFormatter,
  },
  {
    title: "AV", field: "cvss_av", formatter: naFormatter, visible: false,
    sorter: "string", sorterParams: { alignEmptyValues: "bottom" },
    headerFilter: multiSelectHeaderFilter(VECTOR_SELECT_VALUES.AV),
    headerFilterFunc: multiSelectFilterFunc, headerFilterEmptyCheck: multiSelectEmptyCheck,
  },
  {
    title: "AC", field: "cvss_ac", formatter: naFormatter, visible: false,
    sorter: "string", sorterParams: { alignEmptyValues: "bottom" },
    headerFilter: multiSelectHeaderFilter(VECTOR_SELECT_VALUES.AC),
    headerFilterFunc: multiSelectFilterFunc, headerFilterEmptyCheck: multiSelectEmptyCheck,
  },
  {
    title: "AT", field: "cvss_at", formatter: naFormatter, visible: false,
    sorter: "string", sorterParams: { alignEmptyValues: "bottom" },
    headerFilter: multiSelectHeaderFilter(VECTOR_SELECT_VALUES.AT),
    headerFilterFunc: multiSelectFilterFunc, headerFilterEmptyCheck: multiSelectEmptyCheck,
  },
  {
    title: "PR", field: "cvss_pr", formatter: naFormatter, visible: false,
    sorter: "string", sorterParams: { alignEmptyValues: "bottom" },
    headerFilter: multiSelectHeaderFilter(VECTOR_SELECT_VALUES.PR),
    headerFilterFunc: multiSelectFilterFunc, headerFilterEmptyCheck: multiSelectEmptyCheck,
  },
  {
    title: "UI", field: "cvss_ui", formatter: naFormatter, visible: false,
    sorter: "string", sorterParams: { alignEmptyValues: "bottom" },
    headerFilter: multiSelectHeaderFilter(VECTOR_SELECT_VALUES.UI),
    headerFilterFunc: multiSelectFilterFunc, headerFilterEmptyCheck: multiSelectEmptyCheck,
  },
  {
    title: "Vendor", field: "vendor", headerFilter: "input",
    headerFilterFunc: pipeOrFilterFunc, headerFilterPlaceholder: "e.g. forti|cisco|microsoft",
    sorter: "string", sorterParams: { alignEmptyValues: "bottom" },
    formatter: truncateFormatter(50), tooltip: fullValueTooltip,
  },
  {
    title: "Product", field: "product", headerFilter: "input",
    headerFilterFunc: pipeOrFilterFunc, headerFilterPlaceholder: "e.g. fortios|pan-os|windows",
    sorter: "string", sorterParams: { alignEmptyValues: "bottom" },
    formatter: truncateFormatter(50), tooltip: fullValueTooltip,
  },
  {
    title: "CWE", field: "cwe", headerFilter: "input", visible: false,
    sorter: "string", sorterParams: { alignEmptyValues: "bottom" },
    formatter: cweFormatter, tooltip: fullValueTooltip,
  },
  {
    title: "Last Updated", field: "date_updated", sorter: "string", visible: false,
    sorterParams: { alignEmptyValues: "bottom" },
    formatter: dateFormatter,
  },
  {
    // Explicit (not auto-sized) width -- under fitDataStretch, Tabulator
    // measures each column's own actual content, and this one and its
    // sibling below don't always happen to contain the same longest tier
    // string, so auto-sizing alone can leave them a few pixels apart.
    title: "BOD 26-04 (Exposed)", field: "bod_tier_exposed", sorter: bodTierSorter, width: 180,
    titleFormatter: bodTitleFormatter,
    headerFilter: multiSelectHeaderFilter(Object.fromEntries(BOD_TIER_ORDER.map((t) => [t, t]))),
    headerFilterFunc: multiSelectFilterFunc, headerFilterEmptyCheck: multiSelectEmptyCheck,
    formatter: bodTierFormatter,
  },
  {
    // maxWidth caps it at the same width as its sibling above -- otherwise,
    // being the LAST column, fitDataStretch would grow only this one to
    // fill any leftover space on a wide window, leaving the pair visibly
    // mismatched.
    title: "BOD 26-04 (Not Exposed)", field: "bod_tier_not_exposed", sorter: bodTierSorter,
    width: 180, maxWidth: 180,
    titleFormatter: bodTitleFormatter,
    headerFilter: multiSelectHeaderFilter(Object.fromEntries(BOD_TIER_ORDER.map((t) => [t, t]))),
    headerFilterFunc: multiSelectFilterFunc, headerFilterEmptyCheck: multiSelectEmptyCheck,
    formatter: bodTierFormatter,
  },
];

const table = new Tabulator("#cve-table", {
  layout: "fitDataStretch",
  height: "75vh",
  columns,
  placeholder: "No data",
  columnDefaults: { headerFilterLiveFilter: true },
  initialSort: [{ column: "first_active_date", dir: "desc" }],
});

// Puts the current sort/filters/hidden-columns into a single `state` query
// param (via history.replaceState -- no reload, no new history entries) so
// copying the URL reproduces the exact view for someone else. Restoring on
// load only touches column headers/filter values, not the ~178k rows of
// data itself, so this costs the same as a user clicking/typing those same
// filters by hand -- it doesn't scale with row count.
function getShareableState() {
  return {
    sorters: table.getSorters().map((s) => ({ field: s.field, dir: s.dir })),
    filters: table.getHeaderFilters(),
    hidden: table.getColumns().map((c) => c.getField()).filter((f) => f && !table.getColumn(f).isVisible()),
  };
}

// dataFiltered/dataSorted both fire once as an intrinsic part of the
// initial setData() call, before restoreStateFromURL()'s own
// setHeaderFilterValue/setSort calls (made earlier, at tableBuilt time,
// before there was any data to filter/sort) have actually taken effect --
// without this guard, that first automatic firing would overwrite a
// shared URL's `state` param with an empty snapshot before the real
// restore ever got a chance to run.
let initialLoadComplete = false;

function updateURLFromState() {
  if (!initialLoadComplete) return;
  const state = getShareableState();
  const hasState = state.sorters.length > 0 || state.filters.length > 0 || state.hidden.length > 0;
  const url = new URL(location.href);
  if (hasState) {
    url.searchParams.set("state", JSON.stringify(state));
  } else {
    url.searchParams.delete("state");
  }
  history.replaceState(null, "", url);
}

// Custom header filter editors (multiselect-*, range-filter) keep their own
// DOM/selection state that setHeaderFilterValue() alone won't touch, so a
// restored filter would apply correctly but LOOK unset. Driving them
// through their own checkbox/flatpickr APIs keeps the visible control in
// sync with the filter it's actually applying, same as a user's own click.
function restoreStateFromURL() {
  const raw = new URLSearchParams(location.search).get("state");
  if (!raw) return;
  let state;
  try {
    state = JSON.parse(raw);
  } catch (err) {
    return;
  }

  // Every column's visibility is set explicitly (not just hiding whatever
  // is listed) -- several columns (AV/AC/AT/PR/UI, CWE, Last Updated)
  // default to hidden, so a column the sharer had un-hidden needs an
  // explicit show() here; leaving it untouched would keep it at its
  // built-in default instead of the shared state.
  const hidden = new Set(state.hidden || []);
  for (const col of table.getColumns()) {
    const field = col.getField();
    if (!field || field === "cve_id") continue;
    if (hidden.has(field)) col.hide(); else col.show();
  }

  for (const f of state.filters || []) {
    const col = table.getColumn(f.field);
    if (!col) continue;
    const headerEl = col.getElement();

    if (f.value && typeof f.value === "object" && !Array.isArray(f.value)) {
      // Date range: apply the filter FIRST -- setHeaderFilterValue turned
      // out to redraw/reset this custom editor's own DOM as a side effect,
      // which was silently wiping out Flatpickr's display when done in the
      // other order. Flatpickr initializes inside the header filter's
      // onRendered callback (not guaranteed to have run yet here in
      // tableBuilt) and setHeaderFilterValue's redraw is likewise not
      // guaranteed synchronous, so the display update retries briefly
      // rather than assuming either has already happened.
      table.setHeaderFilterValue(f.field, f.value);
      const dates = [f.value.from, f.value.to].filter(Boolean);
      (function setFlatpickrDate(attemptsLeft) {
        const input = headerEl.querySelector(".range-filter input");
        if (input && input._flatpickr) {
          input._flatpickr.setDate(dates, false);
        } else if (attemptsLeft > 0) {
          setTimeout(() => setFlatpickrDate(attemptsLeft - 1), 20);
        }
      })(15);
    } else if (Array.isArray(f.value)) {
      // Multi-select: check the matching boxes through their own change
      // event so the trigger button's label and the actual filter both
      // update exactly as if the user had clicked them.
      const checkboxes = headerEl.querySelectorAll(".multiselect-option input");
      for (const checkbox of checkboxes) {
        if (f.value.includes(checkbox.value) && !checkbox.checked) {
          checkbox.checked = true;
          checkbox.dispatchEvent(new Event("change"));
        }
      }
    } else {
      // Plain built-in "input" editors (Vendor/Product/CVE ID/CWE/Min
      // score) -- Tabulator keeps these in sync on its own.
      table.setHeaderFilterValue(f.field, f.value);
    }
  }

  if (state.sorters && state.sorters.length) {
    // getSorters() returns {field, dir}; setSort() takes {column, dir} --
    // an asymmetric API, not a typo.
    table.setSort(state.sorters.map((s) => ({ column: s.field, dir: s.dir })));
  }
}

// Native title attribute, not Tabulator's headerTooltip -- that module
// tracks one shared popup across all columns and doesn't reliably hide it
// when the mouse moves directly from a tooltipped header to a
// non-tooltipped one, which would leak this text onto AV/AC/AT/PR/UI. A
// native tooltip is scoped to this exact element by the browser itself.
table.on("tableBuilt", () => {
  // Before the column-toggle checkboxes are built below, so their checked
  // state already reflects any columns a shared URL hid.
  restoreStateFromURL();

  const titleEl = table.getColumn("cvss_score").getElement().querySelector(".tabulator-col-title");
  if (titleEl) titleEl.title = CVSS_VERSION_TOOLTIP;

  const bodExposedTitleEl = table.getColumn("bod_tier_exposed").getElement().querySelector(".tabulator-col-title");
  if (bodExposedTitleEl) bodExposedTitleEl.title = bodTierTooltip(true);

  const bodNotExposedTitleEl = table.getColumn("bod_tier_not_exposed").getElement().querySelector(".tabulator-col-title");
  if (bodNotExposedTitleEl) bodNotExposedTitleEl.title = bodTierTooltip(false);

  // Lets a user hide columns they don't care about, on any screen size --
  // a manual alternative to Tabulator's own device-width-driven
  // responsiveLayout, which fought badly with fitDataStretch on resize
  // (see git history). CVE ID is left out since it's frozen/always needed
  // to identify a row at all.
  const columnTogglePanel = document.getElementById("column-toggle-panel");
  for (const col of table.getColumns()) {
    const field = col.getField();
    if (!field || field === "cve_id") continue;
    const label = document.createElement("label");
    label.classList.add("column-toggle-option");
    const checkbox = document.createElement("input");
    checkbox.type = "checkbox";
    checkbox.checked = col.isVisible();
    checkbox.addEventListener("change", () => {
      if (checkbox.checked) col.show(); else col.hide();
      updateURLFromState();
    });
    label.appendChild(checkbox);
    label.appendChild(document.createTextNode(" " + col.getDefinition().title));
    columnTogglePanel.appendChild(label);
  }

  // "No data" (the placeholder set above) is meant for a genuinely empty
  // result -- e.g. filters that match nothing -- not for "hasn't loaded
  // yet", which looks identical and reads as the site being broken.
  // table.alert() is a separate overlay that can cover that first-load
  // window without touching the placeholder's own meaning. Cleared once
  // setData succeeds (or replaced with an error message on failure) below.
  table.alert("Loading data…");
});

// A plain reload with no `state` query param already goes through the
// exact same path a fresh visit takes -- no need to hand-roll code to
// clear every filter/sorter/hidden column individually.
document.getElementById("reset-view-btn").addEventListener("click", () => {
  location.href = location.pathname;
});

// Reads location.href fresh at click time (not a static href baked in
// ahead of time) so sharing also carries along whatever filtered/sorted
// view is currently active via ?state=, same link a user would get from
// the address bar itself.
const SHARE_TEXT = "Vulnrichment Viewer -- filter CISA's Vulnrichment CVE data by exploitation status and CVSS, with BOD 26-04 remediation deadlines.";

function setupShareLink(id, buildUrl) {
  const el = document.getElementById(id);
  if (!el) return;
  el.addEventListener("click", (e) => {
    e.preventDefault();
    window.open(buildUrl(location.href, SHARE_TEXT), "_blank", "noopener");
  });
}

setupShareLink("share-x", (url, text) =>
  `https://twitter.com/intent/tweet?url=${encodeURIComponent(url)}&text=${encodeURIComponent(text)}`);
setupShareLink("share-linkedin", (url) =>
  `https://www.linkedin.com/sharing/share-offsite/?url=${encodeURIComponent(url)}`);
setupShareLink("share-reddit", (url, text) =>
  `https://www.reddit.com/submit?url=${encodeURIComponent(url)}&title=${encodeURIComponent(text)}`);
setupShareLink("share-whatsapp", (url, text) =>
  `https://wa.me/?text=${encodeURIComponent(text + " " + url)}`);

const columnToggleBtn = document.getElementById("column-toggle-btn");
const columnTogglePanelEl = document.getElementById("column-toggle-panel");
columnToggleBtn.addEventListener("click", (e) => {
  e.stopPropagation();
  columnTogglePanelEl.hidden = !columnTogglePanelEl.hidden;
});
document.addEventListener("click", (e) => {
  if (!columnTogglePanelEl.hidden && !columnTogglePanelEl.contains(e.target) && e.target !== columnToggleBtn) {
    columnTogglePanelEl.hidden = true;
  }
});

let totalRowCount = 0;
const filterCountEl = document.getElementById("filter-count");

// Fires on every header-filter change (and once on initial load) with the
// full set of rows currently passing all filters -- not just the visible
// page -- so this always matches what "Export CSV" would actually export.
table.on("dataFiltered", (filters, rows) => {
  filterCountEl.textContent = rows.length === totalRowCount
    ? `${totalRowCount.toLocaleString()} rows`
    : `${rows.length.toLocaleString()} / ${totalRowCount.toLocaleString()} rows match`;
  updateURLFromState();
});

table.on("dataSorted", () => {
  updateURLFromState();
});

// Guard rail, not a hard technical limit -- the browser can build a CSV of
// any size. This just keeps exports to something a spreadsheet-review
// workflow can realistically use, and forces narrowing down (rather than
// silently exporting the entire ~162k-row dataset) if filters are too broad.
const MAX_CSV_EXPORT_ROWS = 5000;

const exportStatus = document.getElementById("export-status");

document.getElementById("export-csv").addEventListener("click", () => {
  // "active" = rows currently passing all header filters, in their current
  // sort order -- not just the visible page. Same set download() would use.
  const filteredCount = table.getDataCount("active");

  if (filteredCount > MAX_CSV_EXPORT_ROWS) {
    exportStatus.textContent =
      `${filteredCount.toLocaleString()} rows match -- narrow filters to ${MAX_CSV_EXPORT_ROWS.toLocaleString()} or fewer to export.`;
    exportStatus.classList.add("error");
    return;
  }

  exportStatus.textContent = "";
  exportStatus.classList.remove("error");
  table.download("csv", "vulnviewer-export.csv");
});

function parseJsonLines(text) {
  const rows = [];
  for (const line of text.split("\n")) {
    if (line) rows.push(JSON.parse(line));
  }
  return rows;
}

function fetchJsonl(path) {
  return fetch(path, { cache: "no-cache" }).then((res) => {
    if (!res.ok) throw new Error(`HTTP ${res.status} for ${path}`);
    return res.text();
  }).then(parseJsonLines);
}

// "no-cache" (not "no-store") -- forces a revalidation request every load
// rather than trusting GitHub Pages' CDN cache headers blindly, but still
// lets the server return a cheap 304 when the data hasn't changed since the
// last fetch. The data updates automatically every few minutes; without
// this, a long-lived cached copy could silently show stale CVE data after a
// plain reload.
//
// The dataset is split across cves-0.jsonl .. cves-N.jsonl (see
// export_json.py -- one file per hash shard, kept under GitHub's 100MB
// per-file limit and each committed uncompressed so git can delta-compress
// between runs). GitHub Pages' CDN gzips them over the wire on its own, so
// fetch()/text() already receive plain text -- no manual
// DecompressionStream handling needed here.
fetch("data/meta.json", { cache: "no-cache" })
  .then((res) => {
    if (!res.ok) throw new Error(`HTTP ${res.status}`);
    return res.json();
  })
  .then((meta) => {
    document.getElementById("status").textContent =
      `${meta.cve_count.toLocaleString()} records / last updated: ${trimMillis(meta.generated_at)}`;
    totalRowCount = meta.cve_count;

    const shardFetches = [];
    for (let i = 0; i < meta.shard_count; i++) {
      shardFetches.push(fetchJsonl(`data/cves-${i}.jsonl`));
    }
    return Promise.all(shardFetches);
  })
  .then((shardRowArrays) => {
    const rows = shardRowArrays.flat();

    // Derive AV/AC/PR/UI from the primary CVSS vector, and both BOD 26-04
    // timelines, client-side (no backend/schema change needed for either).
    for (const row of rows) {
      const comp = parseVectorComponents(row.cvss_vector);
      row.cvss_av = comp.AV || null;
      row.cvss_ac = comp.AC || null;
      row.cvss_at = comp.AT || null;
      row.cvss_pr = comp.PR || null;
      row.cvss_ui = comp.UI || null;
      row.bod_tier_exposed = bodTierFor(row, true);
      row.bod_tier_not_exposed = bodTierFor(row, false);
    }

    // dataFiltered/dataSorted fire internally as part of setData's own
    // rendering, before the promise it returns resolves -- initialLoadComplete
    // must flip only after that settles, or the guard in updateURLFromState()
    // above wouldn't actually catch that first automatic firing.
    table.setData(rows).then(() => {
      table.clearAlert();
      initialLoadComplete = true;
    });
  })
  .catch((err) => {
    document.getElementById("status").textContent = `Failed to load data: ${err.message}`;
    table.alert(`Failed to load data: ${escapeHtml(err.message)}`, "error");
  });
