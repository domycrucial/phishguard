/**
 * dashboard.js – PhishGuard Analytics Dashboard JavaScript.
 * Loads stats, renders Chart.js charts, populates history table,
 * builds rule frequency heatmap, handles pagination & filtering.
 */

// Shared Chart.js instances
let trendChartInst     = null;
let breakdownChartInst = null;

// Pagination state
let currentPage        = 1;
const perPage          = 15;   // Rows per page
let currentFilter      = "all";

// ─── Initialise ───────────────────────────────────
document.addEventListener("DOMContentLoaded", () => {
  loadDashboard();

  // Refresh button
  document.getElementById("refreshBtn")?.addEventListener("click", loadDashboard);

  // Classification filter for history table
  document.getElementById("filterClass")?.addEventListener("change", e => {
    currentFilter = e.target.value;
    currentPage   = 1;   // Reset to first page on filter change
    loadHistory();
  });

  // Pagination buttons
  document.getElementById("prevPage")?.addEventListener("click", () => {
    if (currentPage > 1) { currentPage--; loadHistory(); }
  });
  document.getElementById("nextPage")?.addEventListener("click", () => {
    currentPage++;
    loadHistory();
  });
});

// ─── Load all dashboard data ──────────────────────
async function loadDashboard() {
  await Promise.all([loadStats(), loadHistory()]);
}

// ═══════════════════════════════════════════════════
//  STATS LOADER
// ═══════════════════════════════════════════════════
async function loadStats() {
  try {
    const res  = await fetch("/api/v1/stats");
    const data = await res.json();

    if (!data.success) return;

    // ── Stats cards ──
    setEl("dashTotal",      data.total);
    setEl("dashPhishing",   data.phishing);
    setEl("dashLegitimate", data.legitimate);
    setEl("dashAvgScore",   data.avg_risk_score?.toFixed(1) || "0");

    // ── Trend line chart ──
    renderTrendChart(data.trend || []);

    // ── Breakdown doughnut chart ──
    renderBreakdownChart(data);

    // ── Rule heatmap ──
    renderHeatmap(data.top_rules || []);

  } catch (err) {
    console.error("[Dashboard] Stats load error:", err);
  }
}

// ── Helper: set element text content ──
function setEl(id, value) {
  const el = document.getElementById(id);
  if (el) el.textContent = value;
}

// ═══════════════════════════════════════════════════
//  TREND LINE CHART (14 days)
// ═══════════════════════════════════════════════════
function renderTrendChart(trendData) {
  const canvas = document.getElementById("trendChart");
  if (!canvas) return;

  const isDark  = document.documentElement.getAttribute("data-theme") === "dark";
  const gridClr = isDark ? "#334155" : "#E5E7EB";
  const textClr = isDark ? "#94A3B8" : "#6B7280";

  const labels   = trendData.map(d => d.date.slice(5));   // MM-DD format
  const totals   = trendData.map(d => d.total);
  const phishing = trendData.map(d => d.phishing);

  if (trendChartInst) { trendChartInst.destroy(); trendChartInst = null; }

  trendChartInst = new Chart(canvas, {
    type: "line",
    data: {
      labels,
      datasets: [
        {
          label:           "Total Emails",
          data:            totals,
          borderColor:     "#3B82F6",
          backgroundColor: "rgba(59,130,246,0.08)",
          fill:            true,
          tension:         0.35,
          pointRadius:     3,
        },
        {
          label:           "Phishing",
          data:            phishing,
          borderColor:     "#DC2626",
          backgroundColor: "rgba(220,38,38,0.08)",
          fill:            true,
          tension:         0.35,
          pointRadius:     3,
        }
      ]
    },
    options: {
      responsive: true,
      interaction: { intersect: false, mode: "index" },
      plugins: { legend: { position: "top", labels: { font: { size: 12 }, color: textClr } } },
      scales: {
        x: { grid: { color: gridClr }, ticks: { color: textClr, font: { size: 11 } } },
        y: { grid: { color: gridClr }, ticks: { color: textClr, font: { size: 11 } }, beginAtZero: true },
      }
    }
  });
}

// ═══════════════════════════════════════════════════
//  BREAKDOWN DOUGHNUT CHART
// ═══════════════════════════════════════════════════
function renderBreakdownChart(data) {
  const canvas = document.getElementById("breakdownChart");
  if (!canvas) return;

  if (breakdownChartInst) { breakdownChartInst.destroy(); breakdownChartInst = null; }

  const labels = ["Phishing", "Legitimate"];
  const values = [data.phishing, data.legitimate];
  const colors = ["#DC2626", "#16A34A"];

  breakdownChartInst = new Chart(canvas, {
    type: "doughnut",
    data: {
      labels,
      datasets: [{
        data:            values,
        backgroundColor: colors,
        borderWidth:     2,
        borderColor:     document.documentElement.getAttribute("data-theme") === "dark" ? "#1E293B" : "#FFF",
      }]
    },
    options: {
      cutout: "58%",
      plugins: {
        legend: { display: false },   // Custom legend below
        tooltip: {
          callbacks: {
            label: ctx => ` ${ctx.label}: ${ctx.parsed} (${data.total ? Math.round(ctx.parsed/data.total*100) : 0}%)`
          }
        }
      }
    }
  });

  // Custom legend below the chart
  const legendEl = document.getElementById("breakdownLegend");
  if (legendEl) {
    legendEl.innerHTML = labels.map((l, i) => `
      <div class="legend-item">
        <span class="legend-dot" style="background:${colors[i]}"></span>
        ${l}: <strong>${values[i]}</strong>
      </div>`).join("");
  }
}

// ═══════════════════════════════════════════════════
//  RULE HEATMAP
// ═══════════════════════════════════════════════════
function renderHeatmap(rules) {
  const container = document.getElementById("ruleHeatmap");
  if (!container) return;
  container.innerHTML = "";

  if (!rules.length) {
    container.innerHTML = `<p style="color:var(--text-muted);text-align:center;padding:20px">No trigger data yet.</p>`;
    return;
  }

  const maxCount = Math.max(...rules.map(r => r.count), 1);

  rules.forEach(rule => {
    const pct = (rule.count / maxCount) * 100;   // Width as % of max
    const row = document.createElement("div");
    row.className = "heatmap-row";
    row.innerHTML = `
      <span class="heatmap-label" title="${escHtml(rule.name)}">${escHtml(rule.rule_id)}: ${escHtml(rule.name)}</span>
      <div class="heatmap-bar-wrap">
        <div class="heatmap-bar" style="width:${pct}%"></div>
      </div>
      <span class="heatmap-count">${rule.count}</span>`;
    container.appendChild(row);
  });
}

// ═══════════════════════════════════════════════════
//  HISTORY TABLE
// ═══════════════════════════════════════════════════
async function loadHistory() {
  const tbody = document.getElementById("fullHistoryBody");
  if (!tbody) return;
  tbody.innerHTML = `<tr><td colspan="8" class="table-empty"><i class="ti ti-loader ti-spin"></i> Loading…</td></tr>`;

  try {
    const url = `/api/v1/history?page=${currentPage}&per_page=${perPage}&classification=${currentFilter}`;
    const res  = await fetch(url);
    const data = await res.json();

    if (!data.success || !data.items.length) {
      tbody.innerHTML = `<tr><td colspan="8" class="table-empty">No analyses found.</td></tr>`;
      updatePagination(0, 0);
      return;
    }

    tbody.innerHTML = data.items.map((item, i) => {
      const scoreClass = item.risk_score >= 60 ? "score-high"
                       : item.risk_score >= 30 ? "score-medium"
                       : "score-low";
      const clfClass = `clf-${item.classification}`;
      const dateStr  = item.analysed_at ? new Date(item.analysed_at).toLocaleString() : "—";

      return `
        <tr>
          <td>${(currentPage - 1) * perPage + i + 1}</td>
          <td>${escHtml(truncate(item.sender, 32))}</td>
          <td>${escHtml(truncate(item.subject, 40))}</td>
          <td><span class="score-pill ${scoreClass}">${item.risk_score}</span></td>
          <td><span class="clf-badge ${clfClass}">${item.classification}</span></td>
          <td>${Math.round(item.confidence * 100)}%</td>
          <td>${dateStr}</td>
          <td>
            <a href="/api/v1/export/${item.id}" target="_blank" class="btn btn-sm btn-outline"
               title="Download PDF report">
              <i class="ti ti-file-type-pdf"></i>
            </a>
          </td>
        </tr>`;
    }).join("");

    updatePagination(data.page, data.pages);

  } catch (err) {
    tbody.innerHTML = `<tr><td colspan="8" class="table-empty text-danger">Failed to load history.</td></tr>`;
    console.error("[Dashboard] History load error:", err);
  }
}

function updatePagination(page, totalPages) {
  const pageInfo = document.getElementById("pageInfo");
  const prevBtn  = document.getElementById("prevPage");
  const nextBtn  = document.getElementById("nextPage");

  if (pageInfo) pageInfo.textContent = `Page ${page} of ${totalPages || 1}`;
  if (prevBtn)  prevBtn.disabled = (page <= 1);
  if (nextBtn)  nextBtn.disabled = (page >= totalPages);
}

// ── Utilities ──
function truncate(str, max) {
  if (!str) return "—";
  return str.length > max ? str.slice(0, max) + "…" : str;
}

function escHtml(str) {
  if (!str) return "";
  return String(str).replace(/&/g,"&amp;").replace(/</g,"&lt;").replace(/>/g,"&gt;");
}
