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
    title: "Exploitation", field: "exploitation",
    sorter: "string", sorterParams: { alignEmptyValues: "bottom" },
    headerFilter: multiSelectHeaderFilter({ none: "none", poc: "poc", active: "active" }),
    headerFilterFunc: multiSelectFilterFunc, headerFilterEmptyCheck: multiSelectEmptyCheck,
    formatter: exploitationFormatter,
  },
  {
    title: "Automatable", field: "automatable",
    sorter: "string", sorterParams: { alignEmptyValues: "bottom" },
    headerFilter: multiSelectHeaderFilter({ yes: "yes", no: "no" }),
    headerFilterFunc: multiSelectFilterFunc, headerFilterEmptyCheck: multiSelectEmptyCheck,
    formatter: naFormatter,
  },
  {
    title: "Technical Impact", field: "technical_impact",
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
    title: "AV", field: "cvss_av", formatter: naFormatter,
    sorter: "string", sorterParams: { alignEmptyValues: "bottom" },
    headerFilter: multiSelectHeaderFilter(VECTOR_SELECT_VALUES.AV),
    headerFilterFunc: multiSelectFilterFunc, headerFilterEmptyCheck: multiSelectEmptyCheck,
  },
  {
    title: "AC", field: "cvss_ac", formatter: naFormatter,
    sorter: "string", sorterParams: { alignEmptyValues: "bottom" },
    headerFilter: multiSelectHeaderFilter(VECTOR_SELECT_VALUES.AC),
    headerFilterFunc: multiSelectFilterFunc, headerFilterEmptyCheck: multiSelectEmptyCheck,
  },
  {
    title: "AT", field: "cvss_at", formatter: naFormatter,
    sorter: "string", sorterParams: { alignEmptyValues: "bottom" },
    headerFilter: multiSelectHeaderFilter(VECTOR_SELECT_VALUES.AT),
    headerFilterFunc: multiSelectFilterFunc, headerFilterEmptyCheck: multiSelectEmptyCheck,
  },
  {
    title: "PR", field: "cvss_pr", formatter: naFormatter,
    sorter: "string", sorterParams: { alignEmptyValues: "bottom" },
    headerFilter: multiSelectHeaderFilter(VECTOR_SELECT_VALUES.PR),
    headerFilterFunc: multiSelectFilterFunc, headerFilterEmptyCheck: multiSelectEmptyCheck,
  },
  {
    title: "UI", field: "cvss_ui", formatter: naFormatter,
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
    title: "CWE", field: "cwe", headerFilter: "input",
    sorter: "string", sorterParams: { alignEmptyValues: "bottom" },
    formatter: cweFormatter, tooltip: fullValueTooltip,
  },
  {
    title: "Last Updated", field: "date_updated", sorter: "string",
    sorterParams: { alignEmptyValues: "bottom" },
    formatter: dateFormatter,
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

// Native title attribute, not Tabulator's headerTooltip -- that module
// tracks one shared popup across all columns and doesn't reliably hide it
// when the mouse moves directly from a tooltipped header to a
// non-tooltipped one, which would leak this text onto AV/AC/AT/PR/UI. A
// native tooltip is scoped to this exact element by the browser itself.
table.on("tableBuilt", () => {
  const titleEl = table.getColumn("cvss_score").getElement().querySelector(".tabulator-col-title");
  if (titleEl) titleEl.title = CVSS_VERSION_TOOLTIP;
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

    // Derive AV/AC/PR/UI from the primary CVSS vector client-side (no
    // backend/schema change needed).
    for (const row of rows) {
      const comp = parseVectorComponents(row.cvss_vector);
      row.cvss_av = comp.AV || null;
      row.cvss_ac = comp.AC || null;
      row.cvss_at = comp.AT || null;
      row.cvss_pr = comp.PR || null;
      row.cvss_ui = comp.UI || null;
    }

    table.setData(rows);
  })
  .catch((err) => {
    document.getElementById("status").textContent = `Failed to load data: ${err.message}`;
  });
