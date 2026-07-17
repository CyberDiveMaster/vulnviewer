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

function cveLinkFormatter(cell) {
  const v = cell.getValue();
  if (!v) return "";
  return `<a href="https://www.cve.org/CVERecord?id=${encodeURIComponent(v)}" target="_blank" rel="noopener">${escapeHtml(v)}</a>`;
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

    const selected = new Set();

    function refreshTrigger() {
      if (selected.size === 0) {
        trigger.textContent = "(All)";
        return;
      }
      const labels = Object.entries(options)
        .filter(([value]) => selected.has(value))
        .map(([, label]) => label);
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
      row.appendChild(checkbox);
      row.appendChild(document.createTextNode(" " + label));
      panel.appendChild(row);
    }

    trigger.addEventListener("click", (e) => {
      e.stopPropagation();
      if (panel.hidden) {
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
      panel.hidden = !panel.hidden;
    });
    document.addEventListener("click", (e) => {
      if (!container.contains(e.target)) panel.hidden = true;
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
  PR: { N: "N (None)", L: "L (Low)", H: "H (High)" },
  UI: { N: "N (None)", R: "R (Required)", P: "P (Passive)", A: "A (Active)" },
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
    headerFilter: dateRangeHeaderFilter, headerFilterFunc: dateRangeFilterFunc,
    headerFilterEmptyCheck: dateRangeEmptyCheck, headerFilterLiveFilter: false,
    formatter: dateFormatter,
  },
  {
    title: "Active Since", field: "first_active_date", sorter: "string",
    headerFilter: dateRangeHeaderFilter, headerFilterFunc: dateRangeFilterFunc,
    headerFilterEmptyCheck: dateRangeEmptyCheck, headerFilterLiveFilter: false,
    formatter: dateFormatter,
  },
  {
    title: "Days", field: "days_publish_to_active", sorter: "number",
    formatter: naFormatter,
  },
  {
    title: "Exploitation", field: "exploitation",
    headerFilter: multiSelectHeaderFilter({ none: "none", poc: "poc", active: "active" }),
    headerFilterFunc: multiSelectFilterFunc, headerFilterEmptyCheck: multiSelectEmptyCheck,
    formatter: naFormatter,
  },
  {
    title: "Automatable", field: "automatable",
    headerFilter: multiSelectHeaderFilter({ yes: "yes", no: "no" }),
    headerFilterFunc: multiSelectFilterFunc, headerFilterEmptyCheck: multiSelectEmptyCheck,
    formatter: naFormatter,
  },
  {
    title: "Technical Impact", field: "technical_impact",
    headerFilter: multiSelectHeaderFilter({ partial: "partial", total: "total" }),
    headerFilterFunc: multiSelectFilterFunc, headerFilterEmptyCheck: multiSelectEmptyCheck,
    formatter: naFormatter,
  },
  {
    title: "CVSS Score", field: "cvss_score", sorter: "number",
    headerFilter: "input", headerFilterFunc: minScoreFilterFunc,
    headerFilterPlaceholder: "Min score", formatter: naFormatter,
    headerTooltip: CVSS_VERSION_TOOLTIP,
  },
  {
    title: "AV", field: "cvss_av", formatter: naFormatter,
    headerFilter: multiSelectHeaderFilter(VECTOR_SELECT_VALUES.AV),
    headerFilterFunc: multiSelectFilterFunc, headerFilterEmptyCheck: multiSelectEmptyCheck,
    headerTooltip: CVSS_VERSION_TOOLTIP,
  },
  {
    title: "AC", field: "cvss_ac", formatter: naFormatter,
    headerFilter: multiSelectHeaderFilter(VECTOR_SELECT_VALUES.AC),
    headerFilterFunc: multiSelectFilterFunc, headerFilterEmptyCheck: multiSelectEmptyCheck,
    headerTooltip: CVSS_VERSION_TOOLTIP,
  },
  {
    title: "PR", field: "cvss_pr", formatter: naFormatter,
    headerFilter: multiSelectHeaderFilter(VECTOR_SELECT_VALUES.PR),
    headerFilterFunc: multiSelectFilterFunc, headerFilterEmptyCheck: multiSelectEmptyCheck,
    headerTooltip: CVSS_VERSION_TOOLTIP,
  },
  {
    title: "UI", field: "cvss_ui", formatter: naFormatter,
    headerFilter: multiSelectHeaderFilter(VECTOR_SELECT_VALUES.UI),
    headerFilterFunc: multiSelectFilterFunc, headerFilterEmptyCheck: multiSelectEmptyCheck,
    headerTooltip: CVSS_VERSION_TOOLTIP,
  },
  {
    title: "Vendor", field: "vendor", headerFilter: "input",
    formatter: truncateFormatter(50), tooltip: fullValueTooltip,
  },
  {
    title: "Product", field: "product", headerFilter: "input",
    formatter: truncateFormatter(50), tooltip: fullValueTooltip,
  },
  {
    title: "CWE", field: "cwe", headerFilter: "input",
    formatter: truncateFormatter(50), tooltip: fullValueTooltip,
  },
  {
    title: "Last Updated", field: "date_updated", sorter: "string",
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

async function decodeMaybeGzip(buffer) {
  // The committed file is gzip-compressed (raw JSON is ~150MB, over
  // GitHub's 100MB push limit; gzipped it's ~10MB). Detect the gzip magic
  // bytes (1f 8b) and only decompress if present -- if a CDN/proxy ever
  // transparently decodes Content-Encoding on the way through, the bytes
  // here would already be plain JSON text, so fall back to reading as-is.
  const bytes = new Uint8Array(buffer);
  const isGzip = bytes.length > 2 && bytes[0] === 0x1f && bytes[1] === 0x8b;
  if (isGzip && typeof DecompressionStream !== "undefined") {
    const stream = new Blob([buffer]).stream().pipeThrough(new DecompressionStream("gzip"));
    return new Response(stream).text();
  }
  return new TextDecoder("utf-8").decode(buffer);
}

// "no-cache" (not "no-store") -- forces a revalidation request every load
// rather than trusting GitHub Pages' CDN cache headers blindly, but still
// lets the server return a cheap 304 when the data hasn't changed since the
// last fetch. The data updates automatically twice a day; without this, a
// long-lived cached copy could silently show stale CVE data after a plain
// reload.
fetch("data/cves.json.gz", { cache: "no-cache" })
  .then((res) => {
    if (!res.ok) throw new Error(`HTTP ${res.status}`);
    return res.arrayBuffer();
  })
  .then(decodeMaybeGzip)
  .then((text) => JSON.parse(text))
  .then((payload) => {
    document.getElementById("status").textContent =
      `${payload.cve_count.toLocaleString()} records / last updated: ${payload.generated_at}`;
    totalRowCount = payload.cve_count;

    // Derive AV/AC/PR/UI from the primary CVSS vector client-side (no
    // backend/schema change needed).
    for (const row of payload.rows) {
      const comp = parseVectorComponents(row.cvss_vector);
      row.cvss_av = comp.AV || null;
      row.cvss_ac = comp.AC || null;
      row.cvss_pr = comp.PR || null;
      row.cvss_ui = comp.UI || null;
    }

    table.setData(payload.rows);
  })
  .catch((err) => {
    document.getElementById("status").textContent = `Failed to load data: ${err.message}`;
  });
