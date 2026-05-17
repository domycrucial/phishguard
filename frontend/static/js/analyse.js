/**
 * analyse.js – PhishGuard Analysis Page Logic.
 * Handles:
 *   - Tab switching (form fields / raw email)
 *   - Form submission with fetch API
 *   - Animated progress bar + loading states
 *   - Risk gauge SVG animation
 *   - Rendering rule cards, category chart, email info
 *   - Feedback submission
 *   - PDF export trigger
 */

// ─── State ────────────────────────────────────────────
let currentAnalysisId = null;   // Track the last analysis ID for feedback/export
let categoryChartInstance = null;   // Chart.js instance (must destroy before re-creating)

// ─── DOM References ───────────────────────────────────
const analyseBtn     = document.getElementById("analyseBtn");
const clearBtn       = document.getElementById("clearBtn");
const progressWrap   = document.getElementById("progressWrap");
const progressBar    = document.getElementById("progressBar");
const progressLabel  = document.getElementById("progressLabel");
const resultsSection = document.getElementById("resultsSection");

// ─── Progress Steps ───────────────────────────────────
// Shown sequentially during analysis to give responsive feedback
const PROGRESS_STEPS = [
  { pct: 15, label_en: "Parsing email structure…",      label_sw: "Inasoma muundo wa barua pepe…"  },
  { pct: 40, label_en: "Evaluating 30 detection rules…", label_sw: "Inatathmini sheria 30…"         },
  { pct: 65, label_en: "Scoring risk indicators…",       label_sw: "Inahesabu alama za hatari…"     },
  { pct: 85, label_en: "Generating explanation…",        label_sw: "Inaandaa maelezo…"              },
  { pct: 95, label_en: "Saving to database…",            label_sw: "Inahifadhi kwenye hifadhidata…" },
];

// ─── Initialise ───────────────────────────────────────
document.addEventListener("DOMContentLoaded", () => {
  // Load hero stats on page load
  loadHeroStats();

  // Wire up the tab switcher for input mode
  document.querySelectorAll(".tab[data-tab]").forEach(tab => {
    tab.addEventListener("click", () => switchInputTab(tab.dataset.tab));
  });

  // Wire up result section tabs
  document.querySelectorAll(".tab[data-rtab]").forEach(tab => {
    tab.addEventListener("click", () => switchResultTab(tab.dataset.rtab));
  });

  // Analyse button
  analyseBtn.addEventListener("click", runAnalysis);

  // Clear button
  clearBtn.addEventListener("click", clearForm);

  // New analysis button (shown after results)
  const newBtn = document.getElementById("newAnalysisBtn");
  if (newBtn) newBtn.addEventListener("click", clearForm);

  // PDF export
  const exportBtn = document.getElementById("exportPdfBtn");
  if (exportBtn) exportBtn.addEventListener("click", exportPdf);

  // Feedback buttons
  document.querySelectorAll("[id^='feedbackCorrectBtn'], [id^='feedbackWrongBtn']").forEach(btn => {
    btn.addEventListener("click", () => submitFeedback(btn.dataset.correct === "true"));
  });
  // Alias by ID
  document.getElementById("feedbackCorrectBtn")?.addEventListener("click", () => submitFeedback(true));
  document.getElementById("feedbackWrongBtn")?.addEventListener("click",   () => submitFeedback(false));
});

// ═══════════════════════════════════════════════════
//  INPUT TAB SWITCHING
// ═══════════════════════════════════════════════════
function switchInputTab(targetTab) {
  // Update tab button states
  document.querySelectorAll(".tab[data-tab]").forEach(t => {
    t.classList.toggle("active", t.dataset.tab === targetTab);
    t.setAttribute("aria-selected", (t.dataset.tab === targetTab).toString());
  });

  // Show/hide tab panels
  document.querySelectorAll(".tab-content[id^='panel-']").forEach(panel => {
    const isTarget = panel.id === `panel-${targetTab}`;
    panel.classList.toggle("active", isTarget);
    panel.hidden = !isTarget;   // Also set hidden attribute for accessibility
  });
}

// ═══════════════════════════════════════════════════
//  RESULT TAB SWITCHING
// ═══════════════════════════════════════════════════
function switchResultTab(targetTab) {
  document.querySelectorAll(".tab[data-rtab]").forEach(t => {
    t.classList.toggle("active", t.dataset.rtab === targetTab);
  });
  document.querySelectorAll(".result-tab-content").forEach(panel => {
    const isTarget = panel.id === `rpanel-${targetTab}`;
    panel.hidden = !isTarget;
  });
}

// ═══════════════════════════════════════════════════
//  MAIN ANALYSIS RUNNER
// ═══════════════════════════════════════════════════
async function runAnalysis() {
  const lang = document.getElementById("reportLang")?.value || "en";

  // Collect input data from whichever tab is active
  const isRawMode = document.getElementById("panel-raw") &&
                    !document.getElementById("panel-raw").hidden;

  const payload = isRawMode
    ? {
        raw_email: document.getElementById("inputRaw")?.value || "",
        language:  lang,
      }
    : {
        sender:    document.getElementById("inputSender")?.value    || "",
        recipient: document.getElementById("inputRecipient")?.value || "",
        subject:   document.getElementById("inputSubject")?.value   || "",
        body_text: document.getElementById("inputBody")?.value      || "",
        body_html: document.getElementById("inputHtml")?.value      || "",
        headers:   document.getElementById("inputHeaders")?.value   || "",
        language:  lang,
      };

  // Require at least some content
  const hasContent = Object.values(payload).some(v => v && v.trim && v.trim().length > 0);
  if (!hasContent) {
    showToast("Please enter some email content to analyse.", "error");
    return;
  }

  // ── UI: loading state ──
  setLoadingState(true);
  resultsSection.hidden = true;   // Hide previous results

  // Animate progress bar through steps
  let stepIdx = 0;
  const stepInterval = setInterval(() => {
    if (stepIdx < PROGRESS_STEPS.length) {
      const step  = PROGRESS_STEPS[stepIdx];
      const label = lang === "sw" ? step.label_sw : step.label_en;
      setProgress(step.pct, label);
      stepIdx++;
    }
  }, 350);   // Advance step every 350ms for a smooth feel

  try {
    // ── API call ──
    const res  = await fetch("/api/v1/analyse", {
      method:  "POST",
      headers: { "Content-Type": "application/json" },
      body:    JSON.stringify(payload),
    });

    clearInterval(stepInterval);   // Stop progress animation

    if (!res.ok) {
      const err = await res.json().catch(() => ({}));
      throw new Error(err.error || `Server error: ${res.status}`);
    }

    const data = await res.json();

    if (!data.success) {
      throw new Error(data.error || "Analysis failed.");
    }

    // ── Complete progress bar ──
    setProgress(100, lang === "sw" ? "Imekamilika!" : "Complete!");

    // Short pause so the user sees 100%
    await new Promise(r => setTimeout(r, 400));

    // ── Render results ──
    renderResults(data);
    currentAnalysisId = data.analysis_id;

    // Refresh hero stats
    loadHeroStats();

  } catch (err) {
    clearInterval(stepInterval);
    showToast(`Analysis failed: ${err.message}`, "error");
    console.error("[PhishGuard] Analysis error:", err);
  } finally {
    setLoadingState(false);
    progressWrap.hidden = true;
  }
}

// ═══════════════════════════════════════════════════
//  RENDER RESULTS
// ═══════════════════════════════════════════════════
function renderResults(data) {
  const clf = data.classification;   // "phishing" | "legitimate"
  const score = data.risk_score;
  const exp   = data.explanation || {};

  // ── 1. Result Banner ──
  const banner  = document.getElementById("resultBanner");
  const icon    = document.getElementById("verdictIcon");
  const label   = document.getElementById("verdictLabel");
  const sub     = document.getElementById("verdictSub");

  // Remove previous classification classes
  banner.classList.remove("banner-phishing", "banner-legitimate");
  banner.classList.add(`banner-${clf}`);

  // Set verdict icon + emoji (binary: phishing or legitimate)
  const iconMap   = { phishing: "🎣", legitimate: "✅" };
  const iconClass = { phishing: "icon-phishing", legitimate: "icon-legitimate" };
  icon.textContent = iconMap[clf] || "❓";
  icon.className   = `verdict-icon ${iconClass[clf] || ""}`;

  label.textContent = exp.summary || clf.charAt(0).toUpperCase() + clf.slice(1);
  label.className   = `verdict-label label-${clf}`;
  sub.textContent   = `Risk Score: ${score}/100`;

  // ── 2. Animate Risk Gauge ──
  animateGauge(score, clf);

  // Confidence + meta chips
  document.getElementById("confidenceVal").textContent =
    `${Math.round(data.confidence * 100)}% ${exp.confidence_label || ""}`;
  document.getElementById("rulesVal").textContent = data.rules_triggered;
  document.getElementById("timeVal").textContent  = data.processing_ms;

  // ── 3. Narrative & Recommendations ──
  document.getElementById("narrativeText").textContent     = exp.narrative || "";
  document.getElementById("recommendationText").textContent = exp.recommendations || "";

  // Colour the narrative card border to match binary classification
  const narrative = document.getElementById("narrativeCard");
  narrative.style.borderLeftColor = clf === "phishing" ? "var(--color-danger)" : "var(--color-safe)";

  // ── 4. Triggered Rules Cards ──
  renderRuleCards(exp.triggered_rules || []);

  // Update the tab count badge
  document.getElementById("tabRuleCount").textContent = (exp.triggered_rules || []).length;

  // ── 5. Category Breakdown ──
  renderCategoryBreakdown(exp.category_breakdown || []);

  // ── 6. Email Info Tab ──
  renderEmailInfo(data);

  // ── 7. Show results section with animation ──
  resultsSection.hidden = false;
  resultsSection.scrollIntoView({ behavior: "smooth", block: "start" });
}

// ═══════════════════════════════════════════════════
//  GAUGE ANIMATION
// ═══════════════════════════════════════════════════
function animateGauge(score, clf) {
  const arc   = document.getElementById("gaugeArc");
  const scoreEl = document.getElementById("gaugeScore");

  // SVG arc length for a semicircle of radius 80 = π * r = ~251.2
  const totalLength = 251.2;
  const fillLength  = totalLength * (score / 100);   // How much of the arc to fill
  const dashOffset  = totalLength - fillLength;       // SVG offset = unfilled portion

  // Set colour based on binary classification
  const colourMap = {
    phishing:   "#DC2626",   // Red
    legitimate: "#16A34A",   // Green
  };
  arc.style.stroke          = colourMap[clf] || "#6B7280";
  arc.style.strokeDashoffset = dashOffset;

  // Animate the score number counting up from 0
  let displayScore = 0;
  const target  = Math.round(score);
  const step    = target / 30;   // Complete in ~30 animation frames
  const counter = setInterval(() => {
    displayScore = Math.min(target, displayScore + step);
    scoreEl.textContent = Math.round(displayScore);
    if (Math.round(displayScore) >= target) {
      clearInterval(counter);
      scoreEl.textContent = target;   // Ensure exact final value
    }
  }, 33);   // ~30fps
}

// ═══════════════════════════════════════════════════
//  RULE CARDS RENDERER
// ═══════════════════════════════════════════════════
function renderRuleCards(rules) {
  const container = document.getElementById("rulesContainer");
  container.innerHTML = "";   // Clear previous cards

  if (!rules || rules.length === 0) {
    container.innerHTML = `
      <div style="text-align:center;padding:40px;color:var(--text-muted)">
        <i class="ti ti-shield-check" style="font-size:40px;color:var(--color-safe)"></i>
        <p style="margin-top:12px">No phishing rules were triggered. Email appears legitimate.</p>
      </div>`;
    return;
  }

  rules.forEach(rule => {
    const card = document.createElement("div");
    card.className = "rule-card";

    // Severity badge colour class
    const sevClass = `severity-${rule.severity || "medium"}`;

    card.innerHTML = `
      <div class="rule-card-header" role="button" tabindex="0"
           aria-expanded="false" aria-controls="rule-body-${rule.rule_id}">
        <span class="rule-id">${escHtml(rule.rule_id)}</span>
        <span class="rule-name">${escHtml(rule.name)}</span>
        <span class="severity-badge ${sevClass}">${escHtml(rule.severity?.toUpperCase() || "MEDIUM")}</span>
        <span class="rule-contribution">+${rule.score_contribution.toFixed(2)}</span>
        <i class="ti ti-chevron-down rule-chevron" aria-hidden="true"></i>
      </div>
      <div class="rule-card-body" id="rule-body-${rule.rule_id}">
        <p class="rule-explanation">${escHtml(rule.explanation)}</p>
        <div class="rule-evidence-label">Evidence Matched</div>
        <div class="rule-evidence">${escHtml(rule.evidence || "—")}</div>
        <div style="margin-top:8px;font-size:12px;color:var(--text-muted)">
          Category: <strong>${escHtml(rule.category_label || rule.category)}</strong> &nbsp;|&nbsp;
          Rule Weight: <strong>${rule.weight}</strong>
        </div>
      </div>`;

    // Toggle expand/collapse on click or Enter/Space
    const header = card.querySelector(".rule-card-header");
    const toggle = () => {
      card.classList.toggle("expanded");
      header.setAttribute("aria-expanded", card.classList.contains("expanded").toString());
    };
    header.addEventListener("click", toggle);
    header.addEventListener("keydown", e => {
      if (e.key === "Enter" || e.key === " ") { e.preventDefault(); toggle(); }
    });

    container.appendChild(card);
  });
}

// ═══════════════════════════════════════════════════
//  CATEGORY CHART & LIST
// ═══════════════════════════════════════════════════
function renderCategoryBreakdown(categories) {
  // ── Bar list ──
  const list = document.getElementById("categoryList");
  list.innerHTML = "";

  const maxScore = Math.max(...categories.map(c => c.score), 1);   // For normalising bar widths

  categories.forEach(cat => {
    const barWidth = (cat.score / maxScore) * 100;   // Normalise to 0–100% of max
    const div = document.createElement("div");
    div.className = "cat-item";
    div.innerHTML = `
      <span class="cat-label">${escHtml(cat.label)}</span>
      <div class="cat-bar-wrap">
        <div class="cat-bar" style="width:${barWidth}%;background:var(--color-danger)"></div>
      </div>
      <span class="cat-score">${cat.score.toFixed(1)}</span>`;
    list.appendChild(div);
  });

  // ── Doughnut Chart ──
  const canvas = document.getElementById("categoryChart");
  if (!canvas) return;

  // Destroy previous instance to prevent Chart.js memory leak
  if (categoryChartInstance) {
    categoryChartInstance.destroy();
    categoryChartInstance = null;
  }

  if (categories.length === 0) return;

  const colors = ["#DC2626","#F59E0B","#3B82F6","#8B5CF6","#10B981","#F97316"];

  categoryChartInstance = new Chart(canvas, {
    type: "doughnut",
    data: {
      labels:   categories.map(c => c.label),
      datasets: [{
        data:            categories.map(c => c.score),
        backgroundColor: colors.slice(0, categories.length),
        borderWidth:     2,
        borderColor:     "var(--bg-card)",
      }]
    },
    options: {
      responsive: true,
      plugins: {
        legend: { position: "bottom", labels: { font: { size: 11 }, padding: 12 } },
        tooltip: {
          callbacks: {
            label: ctx => ` ${ctx.label}: ${ctx.parsed.toFixed(1)} pts`
          }
        }
      },
      cutout: "60%",
    }
  });
}

// ═══════════════════════════════════════════════════
//  EMAIL INFO TABLE
// ═══════════════════════════════════════════════════
function renderEmailInfo(data) {
  const tbody = document.querySelector("#emailInfoTable tbody");
  if (!tbody) return;

  const info = data.email_summary || {};
  const rows = [
    ["Sender",         info.sender    || "—"],
    ["Subject",        info.subject   || "—"],
    ["URLs Found",     info.url_count || 0],
    ["HTML Email",     info.has_html  ? "Yes" : "No"],
    ["Risk Score",     `${data.risk_score}/100`],
    ["Classification", data.classification],
    ["Confidence",     `${Math.round(data.confidence * 100)}%`],
    ["Processing",     `${data.processing_ms}ms`],
    ["Analysis ID",    data.analysis_id || "—"],
  ];

  tbody.innerHTML = rows.map(([k, v]) =>
    `<tr><th>${escHtml(k)}</th><td>${escHtml(String(v))}</td></tr>`
  ).join("");
}

// ═══════════════════════════════════════════════════
//  PROGRESS BAR
// ═══════════════════════════════════════════════════
function setProgress(pct, label) {
  progressWrap.hidden = false;
  progressBar.style.width  = `${pct}%`;
  if (progressLabel) progressLabel.textContent = label;
}

function setLoadingState(loading) {
  analyseBtn.disabled = loading;
  const btnLabel   = analyseBtn.querySelector(".btn-label");
  const btnSpinner = analyseBtn.querySelector(".btn-spinner");
  if (btnLabel)   btnLabel.hidden   = loading;
  if (btnSpinner) btnSpinner.hidden = !loading;

  if (loading) {
    progressWrap.hidden = false;
    setProgress(0, "Starting…");
  }
}

// ═══════════════════════════════════════════════════
//  CLEAR FORM
// ═══════════════════════════════════════════════════
function clearForm() {
  // Clear all text inputs and textareas in the form
  ["inputSender","inputRecipient","inputSubject","inputBody",
   "inputHtml","inputHeaders","inputRaw"].forEach(id => {
    const el = document.getElementById(id);
    if (el) el.value = "";
  });

  // Reset gauge
  const arc = document.getElementById("gaugeArc");
  if (arc) { arc.style.strokeDashoffset = "251.2"; arc.style.stroke = "#6B7280"; }
  const scoreEl = document.getElementById("gaugeScore");
  if (scoreEl) scoreEl.textContent = "0";

  // Hide results and progress
  resultsSection.hidden = true;
  progressWrap.hidden   = true;
  currentAnalysisId     = null;

  // Scroll back to input
  window.scrollTo({ top: 0, behavior: "smooth" });
}

// ═══════════════════════════════════════════════════
//  PDF EXPORT
// ═══════════════════════════════════════════════════
async function exportPdf() {
  if (!currentAnalysisId) {
    showToast("No analysis to export.", "error");
    return;
  }
  const lang = document.getElementById("reportLang")?.value || "en";
  const url  = `/api/v1/export/${currentAnalysisId}?lang=${lang}`;
  showToast("Generating PDF report…", "info");

  // Open in new tab — browser handles the file download
  window.open(url, "_blank");
}

// ═══════════════════════════════════════════════════
//  FEEDBACK SUBMISSION
// ═══════════════════════════════════════════════════
async function submitFeedback(isCorrect) {
  if (!currentAnalysisId) {
    showToast("No analysis to provide feedback on.", "error");
    return;
  }

  try {
    const res = await fetch("/api/v1/feedback", {
      method:  "POST",
      headers: { "Content-Type": "application/json" },
      body:    JSON.stringify({
        analysis_result_id: currentAnalysisId,
        is_correct:         isCorrect,
      }),
    });
    const data = await res.json();
    if (data.success) {
      showToast(isCorrect ? "Thanks! Marked as correct ✓" : "Feedback recorded — we'll improve!", "success");
      // Disable both feedback buttons after submission
      document.getElementById("feedbackCorrectBtn")?.setAttribute("disabled", "true");
      document.getElementById("feedbackWrongBtn")?.setAttribute("disabled", "true");
    }
  } catch (err) {
    showToast("Could not submit feedback.", "error");
  }
}

// ═══════════════════════════════════════════════════
//  HERO STATS LOADER
// ═══════════════════════════════════════════════════
async function loadHeroStats() {
  try {
    const res  = await fetch("/api/v1/stats");
    const data = await res.json();
    if (data.success) {
      const setStatEl = (id, val) => {
        const el = document.getElementById(id);
        if (el) el.textContent = val;
      };
      setStatEl("statTotal",      data.total);
      setStatEl("statPhishing",   data.phishing);
      setStatEl("statLegitimate", data.legitimate);
    }
  } catch (_) {
    // Silently fail — hero stats are non-critical
  }
}

// ═══════════════════════════════════════════════════
//  UTILITY: TOAST NOTIFICATION
// ═══════════════════════════════════════════════════
function showToast(message, type = "info") {
  const toast   = document.getElementById("toast");
  const msg     = document.getElementById("toastMsg");
  const iconEl  = document.getElementById("toastIcon");
  if (!toast || !msg) return;

  const iconMap = { info: "ti-info-circle", success: "ti-circle-check", error: "ti-alert-circle" };
  toast.className = `toast toast-${type}`;
  iconEl.className = `toast-icon ti ${iconMap[type] || "ti-info-circle"}`;
  msg.textContent  = message;
  toast.hidden     = false;

  // Auto-dismiss after 4 seconds
  clearTimeout(toast._timeout);
  toast._timeout = setTimeout(() => { toast.hidden = true; }, 4000);
}

// ═══════════════════════════════════════════════════
//  UTILITY: SAFE HTML ESCAPE
// ═══════════════════════════════════════════════════
function escHtml(str) {
  if (!str) return "";
  return String(str)
    .replace(/&/g, "&amp;")
    .replace(/</g, "&lt;")
    .replace(/>/g, "&gt;")
    .replace(/"/g, "&quot;");
}

// Expose showToast globally for other scripts
window.showToast = showToast;
window.escHtml   = escHtml;
