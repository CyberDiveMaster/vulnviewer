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

// Native <select> built by hand rather than via Tabulator's built-in
// "select" editor type -- that type was renamed to "list" in Tabulator 6,
// so `headerFilter: "select"` silently fails to render a dropdown at all
// on the CDN version this page loads. A custom function is not tied to
// that naming/version churn.
function selectHeaderFilter(valuesMap) {
  const options = selectValuesWithNone(valuesMap);
  return function (cell, onRendered, success) {
    const select = document.createElement("select");
    select.classList.add("select-filter");
    for (const [value, label] of Object.entries(options)) {
      select.appendChild(new Option(label, value));
    }
    select.addEventListener("change", () => success(select.value));
    return select;
  };
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
    headerFilter: selectHeaderFilter({ none: "none", poc: "poc", active: "active" }),
    headerFilterFunc: nullableSelectFilterFunc,
    formatter: naFormatter,
  },
  {
    title: "Automatable", field: "automatable", width: 120,
    headerFilter: selectHeaderFilter({ yes: "yes", no: "no" }),
    headerFilterFunc: nullableSelectFilterFunc,
    formatter: naFormatter,
  },
  {
    title: "Technical Impact", field: "technical_impact", width: 150,
    headerFilter: selectHeaderFilter({ partial: "partial", total: "total" }),
    headerFilterFunc: nullableSelectFilterFunc,
    formatter: naFormatter,
  },
  {
    title: "CVSS Score", field: "cvss_score", sorter: "number", width: 110,
    headerFilter: "input", headerFilterFunc: minScoreFilterFunc,
    headerFilterPlaceholder: "Min score", formatter: naFormatter,
  },
  {
    title: "AV", field: "cvss_av", width: 90, formatter: naFormatter,
    headerFilter: selectHeaderFilter(VECTOR_SELECT_VALUES.AV), headerFilterFunc: nullableSelectFilterFunc,
  },
  {
    title: "AC", field: "cvss_ac", width: 90, formatter: naFormatter,
    headerFilter: selectHeaderFilter(VECTOR_SELECT_VALUES.AC), headerFilterFunc: nullableSelectFilterFunc,
  },
  {
    title: "PR", field: "cvss_pr", width: 90, formatter: naFormatter,
    headerFilter: selectHeaderFilter(VECTOR_SELECT_VALUES.PR), headerFilterFunc: nullableSelectFilterFunc,
  },
  {
    title: "UI", field: "cvss_ui", width: 90, formatter: naFormatter,
    headerFilter: selectHeaderFilter(VECTOR_SELECT_VALUES.UI), headerFilterFunc: nullableSelectFilterFunc,
  },
  { title: "Vendor", field: "vendor", headerFilter: "input", formatter: naFormatter, width: 160 },
  { title: "Product", field: "product", headerFilter: "input", formatter: naFormatter, width: 160 },
  { title: "CWE", field: "cwe", headerFilter: "input", formatter: naFormatter, width: 150 },
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
  initialSort: [{ column: "first_active_date", dir: "desc" }],
});

document.getElementById("export-csv").addEventListener("click", () => {
  // No explicit range argument -- Tabulator's default downloadRowRange is
  // "active", i.e. rows currently passing all header filters, in their
  // current sort order. Not just the visible page.
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
