const NONE_SENTINEL = "__none__";

function naFormatter(cell) {
  const v = cell.getValue();
  if (v === null || v === undefined || v === "") {
    return '<span class="na-cell">N/A</span>';
  }
  return v;
}

function cveLinkFormatter(cell) {
  const v = cell.getValue();
  if (!v) return "";
  return `<a href="https://www.cve.org/CVERecord?id=${encodeURIComponent(v)}" target="_blank" rel="noopener">${v}</a>`;
}

function selectValuesWithNone(labels) {
  return { "": "(All)", [NONE_SENTINEL]: "(No assessment)", ...labels };
}

function nullableSelectFilterFunc(headerValue, rowValue) {
  if (headerValue === NONE_SENTINEL) {
    return rowValue === null || rowValue === undefined || rowValue === "";
  }
  return rowValue === headerValue;
}

function minScoreFilterFunc(headerValue, rowValue) {
  if (headerValue === "" || headerValue === null || headerValue === undefined) return true;
  const min = Number(headerValue);
  if (Number.isNaN(min)) return true;
  return rowValue !== null && rowValue !== undefined && Number(rowValue) >= min;
}

function cvssVectorTooltip(e, cell) {
  const row = cell.getRow().getData();
  if (!row.cvss_all || row.cvss_all.length === 0) return "No CVSS data";
  return row.cvss_all
    .map((c) => `[${c.source}] v${c.version}: ${c.vector} (score ${c.base_score ?? "?"})`)
    .join("\n");
}

// --- Date range header filter (from/to), shared by Date Published / Active Since ---

function dateRangeHeaderFilter(cell, onRendered, success) {
  const container = document.createElement("span");
  container.classList.add("range-filter");

  const from = document.createElement("input");
  from.type = "date";
  from.title = "From";

  const to = document.createElement("input");
  to.type = "date";
  to.title = "To";

  function emit() {
    success({ from: from.value, to: to.value });
  }
  from.addEventListener("change", emit);
  to.addEventListener("change", emit);

  container.appendChild(from);
  container.appendChild(to);
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

// --- CVSS vector component parsing (AV/AC/PR/UI), computed client-side ---

const VECTOR_LABELS = {
  AV: { N: "Network", A: "Adjacent", L: "Local", P: "Physical" },
  AC: { L: "Low", H: "High" },
  PR: { N: "None", L: "Low", H: "High" },
  UI: { N: "None", R: "Required", P: "Passive", A: "Active" },
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

function buildVectorSelectValues(rows, field) {
  const seen = new Set();
  for (const row of rows) {
    if (row[field]) seen.add(row[field]);
  }
  const labels = VECTOR_LABELS[field.slice(-2).toUpperCase()] || {};
  const values = {};
  for (const code of Array.from(seen).sort()) {
    values[code] = labels[code] ? `${code} (${labels[code]})` : code;
  }
  return selectValuesWithNone(values);
}

const columns = [
  { title: "CVE ID", field: "cve_id", headerFilter: "input", formatter: cveLinkFormatter, width: 150, frozen: true },
  {
    title: "Date Published", field: "date_published", sorter: "string", width: 220,
    headerFilter: dateRangeHeaderFilter, headerFilterFunc: dateRangeFilterFunc,
    headerFilterEmptyCheck: dateRangeEmptyCheck, headerFilterLiveFilter: false,
  },
  {
    title: "Active Since", field: "first_active_date", sorter: "string", width: 220,
    headerFilter: dateRangeHeaderFilter, headerFilterFunc: dateRangeFilterFunc,
    headerFilterEmptyCheck: dateRangeEmptyCheck, headerFilterLiveFilter: false,
    formatter: naFormatter,
  },
  {
    title: "Exploitation", field: "exploitation", width: 130,
    headerFilter: "select",
    headerFilterParams: { values: selectValuesWithNone({ none: "none", poc: "poc", active: "active" }) },
    headerFilterFunc: nullableSelectFilterFunc,
    formatter: naFormatter,
  },
  {
    title: "Automatable", field: "automatable", width: 120,
    headerFilter: "select",
    headerFilterParams: { values: selectValuesWithNone({ yes: "yes", no: "no" }) },
    headerFilterFunc: nullableSelectFilterFunc,
    formatter: naFormatter,
  },
  {
    title: "Technical Impact", field: "technical_impact", width: 150,
    headerFilter: "select",
    headerFilterParams: { values: selectValuesWithNone({ partial: "partial", total: "total" }) },
    headerFilterFunc: nullableSelectFilterFunc,
    formatter: naFormatter,
  },
  {
    title: "CVSS Score", field: "cvss_score", sorter: "number", width: 110,
    headerFilter: "input", headerFilterFunc: minScoreFilterFunc,
    headerFilterPlaceholder: "Min score", formatter: naFormatter,
  },
  {
    title: "Severity", field: "cvss_severity", width: 120,
    headerFilter: "select",
    headerFilterParams: {
      values: selectValuesWithNone({
        CRITICAL: "CRITICAL", HIGH: "HIGH", MEDIUM: "MEDIUM", LOW: "LOW", NONE: "NONE",
      }),
    },
    headerFilterFunc: nullableSelectFilterFunc,
    formatter: naFormatter,
  },
  {
    title: "CVSS Vector", field: "cvss_vector", headerFilter: "input",
    formatter: naFormatter, tooltip: cvssVectorTooltip, width: 220,
  },
  {
    title: "AV", field: "cvss_av", width: 90, formatter: naFormatter,
    headerFilter: "select", headerFilterFunc: nullableSelectFilterFunc,
    headerFilterParams: { values: selectValuesWithNone({}) },
  },
  {
    title: "AC", field: "cvss_ac", width: 90, formatter: naFormatter,
    headerFilter: "select", headerFilterFunc: nullableSelectFilterFunc,
    headerFilterParams: { values: selectValuesWithNone({}) },
  },
  {
    title: "PR", field: "cvss_pr", width: 90, formatter: naFormatter,
    headerFilter: "select", headerFilterFunc: nullableSelectFilterFunc,
    headerFilterParams: { values: selectValuesWithNone({}) },
  },
  {
    title: "UI", field: "cvss_ui", width: 90, formatter: naFormatter,
    headerFilter: "select", headerFilterFunc: nullableSelectFilterFunc,
    headerFilterParams: { values: selectValuesWithNone({}) },
  },
  { title: "Vendor", field: "vendor", headerFilter: "input", formatter: naFormatter, width: 160 },
  { title: "Product", field: "product", headerFilter: "input", formatter: naFormatter, width: 160 },
  { title: "CWE", field: "cwe", headerFilter: "input", formatter: naFormatter, width: 150 },
  {
    title: "Days: None→Active", field: "days_none_to_active", sorter: "number",
    formatter: naFormatter, width: 150,
  },
  {
    title: "Days: PoC→Active", field: "days_poc_to_active", sorter: "number",
    formatter: naFormatter, width: 150,
  },
  {
    title: "Days: Publish→Active", field: "days_publish_to_active", sorter: "number",
    formatter: naFormatter, width: 160,
  },
  { title: "Last Updated", field: "date_updated", sorter: "string", width: 130 },
];

const table = new Tabulator("#cve-table", {
  layout: "fitDataStretch",
  height: "75vh",
  columns,
  placeholder: "No data",
  columnDefaults: { headerFilterLiveFilter: true },
});

const GLOBAL_SEARCH_FIELDS = ["cve_id", "vendor", "product", "cwe", "cvss_vector"];
let globalSearchFilterFn = null;

document.getElementById("global-search").addEventListener("input", (e) => {
  // addFilter/removeFilter (not setFilter) so this coexists with the
  // per-column header filters instead of replacing the whole filter stack.
  if (globalSearchFilterFn) {
    table.removeFilter(globalSearchFilterFn);
    globalSearchFilterFn = null;
  }
  const term = e.target.value.trim().toLowerCase();
  if (!term) return;
  globalSearchFilterFn = (row) =>
    GLOBAL_SEARCH_FIELDS.some((f) => String(row[f] ?? "").toLowerCase().includes(term));
  table.addFilter(globalSearchFilterFn);
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

fetch("data/cves.json.gz")
  .then((res) => {
    if (!res.ok) throw new Error(`HTTP ${res.status}`);
    return res.arrayBuffer();
  })
  .then(decodeMaybeGzip)
  .then((text) => JSON.parse(text))
  .then((payload) => {
    document.getElementById("status").textContent =
      `${payload.cve_count.toLocaleString()} records / last updated: ${payload.generated_at}`;

    // Derive AV/AC/PR/UI from the primary CVSS vector client-side (no
    // backend/schema change needed), then populate their select filters
    // with only the values actually present in this dataset -- CVSS v3.x
    // and v4.0 vectors use different value sets for some of these
    // components (e.g. UI: N/R in v3 vs N/P/A in v4), so hardcoding one
    // vocabulary would be wrong for the other version.
    for (const row of payload.rows) {
      const comp = parseVectorComponents(row.cvss_vector);
      row.cvss_av = comp.AV || null;
      row.cvss_ac = comp.AC || null;
      row.cvss_pr = comp.PR || null;
      row.cvss_ui = comp.UI || null;
    }

    table.setData(payload.rows).then(() => {
      for (const field of ["cvss_av", "cvss_ac", "cvss_pr", "cvss_ui"]) {
        table.getColumn(field).updateDefinition({
          headerFilterParams: { values: buildVectorSelectValues(payload.rows, field) },
        });
      }
    });
  })
  .catch((err) => {
    document.getElementById("status").textContent = `Failed to load data: ${err.message}`;
  });
