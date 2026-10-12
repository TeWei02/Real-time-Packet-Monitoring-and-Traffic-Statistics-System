/* Measured-performance panel.
 *
 * Reads data/benchmark.json — the output of tools/benchmark.py — and shows where
 * the analysis pipeline actually spends its time. Same constraints as the rest
 * of this page: no third-party code, no build step, everything rendered from the
 * file so regenerating it updates the panel without editing markup.
 *
 * The chart is a stacked bar per capture size. Export is drawn as a separate
 * top segment on purpose: it is matplotlib rendering charts, not analysis, and
 * the throughput figure excludes it.
 */
(function () {
  "use strict";

  var STAGES = [
    { key: "load_s", label: "capture load", colour: "#1d5f86" },
    { key: "parse_s", label: "dissection", colour: "#4cc2ff" },
    { key: "dataframe_s", label: "DataFrame", colour: "#a78bfa" },
    { key: "statistics_s", label: "statistics", colour: "#4ade80" },
    { key: "export_s", label: "export (charts, excluded from pkt/s)", colour: "#fbbf24" }
  ];

  var statusEl = document.getElementById("perf-status");
  var chartEl = document.getElementById("chart-stages");
  var legendEl = document.getElementById("legend-stages");
  var tableEl = document.getElementById("perf-table");
  var noteEl = document.getElementById("perf-note");

  function fail(message) {
    statusEl.textContent = message;
    statusEl.className = "status bad";
  }

  function niceTop(value, ticks) {
    var raw = value / ticks;
    var mag = Math.pow(10, Math.floor(Math.log(raw) / Math.LN10));
    var norm = raw / mag;
    var step = (norm <= 1 ? 1 : norm <= 2 ? 2 : norm <= 2.5 ? 2.5 : norm <= 5 ? 5 : 10) * mag;
    return step * ticks;
  }

  function kb(bytes) {
    return (bytes / 1024).toFixed(1) + " KB";
  }

  function thousands(value) {
    return value.toFixed(0).replace(/\B(?=(\d{3})+(?!\d))/g, ",");
  }

  function total(row) {
    return STAGES.reduce(function (sum, stage) { return sum + row[stage.key]; }, 0);
  }

  /* ------------------------------------------------------------------ chart */
  function drawChart(rows) {
    var W = 780;
    var H = 400;
    var pad = { l: 60, r: 20, t: 34, b: 58 };
    var iw = W - pad.l - pad.r;
    var ih = H - pad.t - pad.b;
    var TICKS = 4;
    var top = niceTop(Math.max.apply(null, rows.map(total)) * 1.12, TICKS);
    var step = top / TICKS;
    var slot = iw / rows.length;
    var barW = Math.min(104, slot * 0.5);

    function yOf(v) { return pad.t + ih - (v / top) * ih; }

    var parts = [];
    parts.push('<svg viewBox="0 0 ' + W + ' ' + H + '" role="img" ' +
      'aria-label="Stage cost per capture size, stacked">');

    for (var g = 0; g <= TICKS; g++) {
      var y = yOf((g / TICKS) * top);
      parts.push('<line x1="' + pad.l + '" y1="' + y.toFixed(1) + '" x2="' + (pad.l + iw) +
        '" y2="' + y.toFixed(1) + '" stroke="#22304a" stroke-width="1"' +
        (g === 0 ? '' : ' stroke-dasharray="3 4"') + '/>');
      parts.push('<text x="' + (pad.l - 9) + '" y="' + (y + 4).toFixed(1) +
        '" fill="#93a4c0" font-size="11" text-anchor="end" font-family="ui-monospace,monospace">' +
        (step < 1 ? ((g / TICKS) * top).toFixed(2) : ((g / TICKS) * top).toFixed(1)) +
        '</text>');
    }
    parts.push('<text x="' + pad.l + '" y="18" fill="#93a4c0" font-size="11">seconds</text>');

    rows.forEach(function (row, i) {
      var cx = pad.l + slot * i + slot / 2;
      var x = cx - barW / 2;
      var cursor = pad.t + ih;
      STAGES.forEach(function (stage) {
        var height = (row[stage.key] / top) * ih;
        if (height <= 0) { return; }
        cursor -= height;
        parts.push('<rect x="' + x.toFixed(1) + '" y="' + cursor.toFixed(1) +
          '" width="' + barW.toFixed(1) + '" height="' + height.toFixed(1) +
          '" fill="' + stage.colour + '" fill-opacity="' +
          (stage.key === "export_s" ? "0.55" : "0.92") + '"/>');
      });
      parts.push('<text x="' + cx.toFixed(1) + '" y="' + (cursor - 12).toFixed(1) +
        '" fill="#e7eef9" font-size="12" text-anchor="middle" font-family="ui-monospace,monospace">' +
        thousands(row.analysis_packets_per_sec) + '</text>');
      parts.push('<text x="' + cx.toFixed(1) + '" y="' + (pad.t + ih + 20) +
        '" fill="#93a4c0" font-size="12" text-anchor="middle" font-family="ui-monospace,monospace">' +
        thousands(row.packets) + '</text>');
      parts.push('<text x="' + cx.toFixed(1) + '" y="' + (pad.t + ih + 36) +
        '" fill="#5f7396" font-size="11" text-anchor="middle">' + kb(row.capture_bytes) + '</text>');
    });

    parts.push('<text x="' + (pad.l + iw / 2) + '" y="' + (H - 8) +
      '" fill="#93a4c0" font-size="12" text-anchor="middle">packets in the capture</text>');
    parts.push('<text x="' + (pad.l + iw / 2) + '" y="' + (pad.t - 18) +
      '" fill="#93a4c0" font-size="11" text-anchor="middle">' +
      'figure above each bar: analysis packets per second (export excluded)</text>');
    parts.push('</svg>');
    chartEl.innerHTML = parts.join("");

    legendEl.innerHTML = STAGES.map(function (stage) {
      return '<span><i style="background:' + stage.colour + '"></i>' + stage.label + '</span>';
    }).join("");
  }

  /* ------------------------------------------------------------------ table */
  function drawTable(rows) {
    var head = "<tr><th>Packets</th><th>Capture</th><th>Load</th><th>Dissect</th>" +
      "<th>DataFrame</th><th>Statistics</th><th>Analysis total</th>" +
      "<th>Analysis pkt/s</th><th>Export</th></tr>";
    var body = rows.map(function (row) {
      return "<tr><td>" + thousands(row.packets) + "</td><td>" + kb(row.capture_bytes) +
        "</td><td>" + row.load_s.toFixed(4) + " s</td><td>" + row.parse_s.toFixed(4) +
        " s</td><td>" + row.dataframe_s.toFixed(4) + " s</td><td>" +
        row.statistics_s.toFixed(4) + " s</td><td>" + row.analysis_s.toFixed(4) +
        " s</td><td>" + thousands(row.analysis_packets_per_sec) + "</td><td>" +
        row.export_s.toFixed(4) + " s</td></tr>";
    }).join("");
    tableEl.innerHTML = "<table>" + head + body + "</table>";
  }

  /* ------------------------------------------------------------------- note */
  function drawNote(data, rows) {
    var largest = rows[rows.length - 1];
    var share = ((largest.load_s / largest.analysis_s) * 100).toFixed(0);
    var afterParsing = largest.dataframe_s + largest.statistics_s;
    var memory = data.memory || {};
    var text = "At " + thousands(largest.packets) + " packets, capture loading is " +
      largest.load_s.toFixed(2) + " s of the " + largest.analysis_s.toFixed(2) +
      " s analysis total (" + share + "%), while dissection is " + largest.parse_s.toFixed(2) +
      " s and everything after it — DataFrame plus statistics — is " +
      afterParsing.toFixed(3) + " s combined.";
    if (memory.peak_mb) {
      text += " Peak traced memory is " + memory.peak_mb + " MB (" +
        (memory.peak_mb * 1024 / largest.packets).toFixed(1) + " KB per packet).";
    }
    if (data.methodology && data.methodology.note) {
      text += " " + data.methodology.note;
    }
    text += " " + data.scope;
    noteEl.textContent = text;
  }

  /* --------------------------------------------------------------- download */
  function downloadSvg(filename) {
    var svg = chartEl.innerHTML;
    if (!svg) { return; }
    var blob = new Blob(['<?xml version="1.0" encoding="UTF-8"?>\n' + svg],
      { type: "image/svg+xml" });
    var url = URL.createObjectURL(blob);
    var link = document.createElement("a");
    link.href = url;
    link.download = filename;
    document.body.appendChild(link);
    link.click();
    document.body.removeChild(link);
    URL.revokeObjectURL(url);
  }

  /* ------------------------------------------------------------------- load */
  // Wire the export button before the fetch. It is independent of loading, and
  // keeping it out of the promise chain means a failure here can never be
  // reported as "could not load the data".
  (function wireExport() {
    var button = document.getElementById("svg-stages");
    if (button && typeof button.addEventListener === "function") {
      button.addEventListener("click", function () {
        downloadSvg("pipeline_stage_cost.svg");
      });
    }
  })();

  fetch("data/benchmark.json", { cache: "no-cache" })
    .then(function (response) {
      if (!response.ok) { throw new Error("HTTP " + response.status); }
      return response.json();
    })
    .then(function (data) {
      var rows = data.scaling || [];
      if (!rows.length) { throw new Error("the file contains no scaling rows"); }
      drawChart(rows);
      drawTable(rows);
      drawNote(data, rows);
      var env = data.environment || {};
      var method = data.methodology || {};
      statusEl.textContent = rows.length + " capture sizes · " + (env.cpu || "unknown CPU") +
        " · median of " + (method.repeat || "?") + " runs · wall clock, time.perf_counter";
      statusEl.className = "status ok";
    })
    .catch(function (error) {
      fail("Could not load data/benchmark.json (" + error.message +
        "). Run tools/benchmark.py to regenerate it.");
    });
})();