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
  return { "": "(すべて)", [NONE_SENTINEL]: "(評価なし)", ...labels };
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
  if (!row.cvss_all || row.cvss_all.length === 0) return "CVSS情報なし";
  return row.cvss_all
    .map((c) => `[${c.source}] v${c.version}: ${c.vector} (score ${c.base_score ?? "?"})`)
    .join("\n");
}

const columns = [
  { title: "CVE ID", field: "cve_id", headerFilter: "input", formatter: cveLinkFormatter, width: 150, frozen: true },
  { title: "公開日", field: "date_published", sorter: "string", headerFilter: "input", width: 130 },
  {
    title: "Active化日", field: "first_active_date", sorter: "string",
    headerFilter: "input", formatter: naFormatter, width: 130,
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
    headerFilterPlaceholder: "最小値", formatter: naFormatter,
  },
  { title: "Severity", field: "cvss_severity", headerFilter: "input", formatter: naFormatter, width: 110 },
  {
    title: "CVSS Vector", field: "cvss_vector", headerFilter: "input",
    formatter: naFormatter, tooltip: cvssVectorTooltip, width: 220,
  },
  { title: "Vendor", field: "vendor", headerFilter: "input", formatter: naFormatter, width: 160 },
  { title: "Product", field: "product", headerFilter: "input", formatter: naFormatter, width: 160 },
  { title: "CWE", field: "cwe", headerFilter: "input", formatter: naFormatter, width: 150 },
  {
    title: "None→Active(日)", field: "days_none_to_active", sorter: "number",
    formatter: naFormatter, width: 140,
  },
  {
    title: "PoC→Active(日)", field: "days_poc_to_active", sorter: "number",
    formatter: naFormatter, width: 140,
  },
  { title: "更新日", field: "date_updated", sorter: "string", width: 130 },
];

const table = new Tabulator("#cve-table", {
  layout: "fitDataStretch",
  height: "75vh",
  columns,
  placeholder: "データがありません",
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
      `${payload.cve_count.toLocaleString()} 件 / 最終更新: ${payload.generated_at}`;
    table.setData(payload.rows);
  })
  .catch((err) => {
    document.getElementById("status").textContent = `データの読み込みに失敗しました: ${err.message}`;
  });
