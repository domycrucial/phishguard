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
 *   - Content masking: email content is visually masked after paste
 *     and base64-encoded before transmission for privacy
 */

// ─── State ────────────────────────────────────────────
let currentAnalysisId = null;       // Track the last analysis ID for feedback/export
let categoryChartInstance = null;   // Chart.js instance (must destroy before re-creating)

// ─── Masking State ────────────────────────────────────
// Stores the real (unmasked) content for each field ID.
// Masking replaces visible textarea text with ● chars while keeping
// the real content here so it can be encoded and sent to the server.
const _realContent = {};  // { fieldId: "actual email text" }
const _maskTimers  = {};  // debounce timers so we don't mask on every keystroke

// IDs of all textarea fields that should support content masking
const MASKABLE_FIELDS = [
  "inputBody", "inputRaw"
];

// ─── Content Masking ──────────────────────────────────

/**
 * Base64-encodes a UTF-8 string for transmission.
 * The server's _decode_field() decodes this before analysis.
 */
function b64Encode(str) {
  try {
    // encodeURIComponent handles non-ASCII, btoa handles the rest
    return btoa(encodeURIComponent(str).replace(
      /%([0-9A-F]{2})/g,
      (_, p) => String.fromCharCode(parseInt(p, 16))
    ));
  } catch (_) {
    return btoa(unescape(encodeURIComponent(str)));
  }
}

/**
 * Replace textarea content with ● characters (same count as words).
 * Stores the real value in _realContent for later submission.
 */
function maskField(fieldId) {
  const el = document.getElementById(fieldId);
  if (!el || !el.value.trim()) return;

  // Only store if we don't already have a stored value (avoid double-masking)
  if (!_realContent[fieldId]) {
    _realContent[fieldId] = el.value;
  }

  // Replace visible text with bullet chars — same character count as words
  const wordCount = el.value.split(/\s+/).filter(Boolean).length;
  el.value = Array(wordCount).fill("●●●●●").join(" ");

  // Visual feedback: set lock icon to "locked" state
  _setMaskIcon(fieldId, true);
}

/**
 * Restore the real content into the textarea.
 */
function unmaskField(fieldId) {
  const el = document.getElementById(fieldId);
  if (!el) return;

  if (_realContent[fieldId] !== undefined) {
    el.value = _realContent[fieldId];
  }
  _setMaskIcon(fieldId, false);
}

/**
 * Toggle mask/unmask for a single field.
 */
function toggleMask(fieldId) {
  if (_realContent[fieldId] !== undefined) {
    // Currently masked — reveal it
    unmaskField(fieldId);
    delete _realContent[fieldId];
  } else {
    maskField(fieldId);
  }
}

/**
 * Update the lock-icon button state (locked / unlocked).
 * Adds .is-locked CSS class so the button turns amber when content is hidden.
 */
function _setMaskIcon(fieldId, isLocked) {
  const btn = document.getElementById(`mask-${fieldId}`);
  if (!btn) return;
  const icon = btn.querySelector("i");
  if (icon) {
    icon.className = isLocked ? "ti ti-lock" : "ti ti-lock-open";
  }
  btn.classList.toggle("is-locked", isLocked);
  btn.title = isLocked ? "Content masked — click to reveal" : "Click to mask content";
}

/**
 * Auto-mask a field 1.5 s after the user stops typing/pasting.
 * Called by the input/paste event listeners set up in DOMContentLoaded.
 */
function scheduleAutoMask(fieldId) {
  clearTimeout(_maskTimers[fieldId]);
  _maskTimers[fieldId] = setTimeout(() => maskField(fieldId), 1500);
}

/**
 * Get the real value for a field — from _realContent if masked, else from DOM.
 */
function getRealValue(fieldId) {
  return _realContent[fieldId] !== undefined
    ? _realContent[fieldId]
    : (document.getElementById(fieldId)?.value || "");
}

/**
 * Validates if the text content "looks" like an email.
 * Rejects random gibberish, single letters, and non-email formats.
 */
function validateEmailContent(text, isRaw) {
  const trimmed = text.trim();

  // 1. Basic length check
  if (trimmed.length < 15) {
    return {
      isValid: false,
      message: "Content too short. Please paste a complete email or message."
    };
  }

  // 2. Raw Email Validation (RFC-2822 structure)
  if (isRaw) {
    const commonHeaders = ["from:", "to:", "subject:", "date:", "received:", "content-type:"];
    const lowerText = trimmed.toLowerCase();
    const headersFound = commonHeaders.filter(h => lowerText.includes(h)).length;

    // A raw email must have at least 2 common headers and some content
    if (headersFound < 2) {
      return {
        isValid: false,
        message: "Invalid Raw Format. A raw email must include standard headers (e.g., From, Subject, To)."
      };
    }
  }
  // 3. Body/Message Validation
  else {
    // Count spaces to detect "long single-word" gibberish
    const spaceCount = (trimmed.match(/\s/g) || []).length;
    const words = trimmed.split(/\s+/).filter(w => w.length > 1);

    // Heuristic: A real email body should have spaces and multiple words
    if (spaceCount < 3 || words.length < 4) {
      return {
        isValid: false,
        message: "Invalid Email Format. Please paste a readable email body with complete sentences."
      };
    }

    // Check for "Keyboard mashing" (too many consonants/randomness)
    // If a word is longer than 25 chars without any punctuation/spaces, it's likely gibberish
    const hasMasher = words.some(w => w.length > 25 && !w.includes(".") && !w.includes("/"));
    if (hasMasher) {
      return {
        isValid: false,
        message: "Content rejected. Random character strings are not valid email content."
      };
    }
  }

  return { isValid: true };
}

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
  console.log("[PhishGuard] App ready.");

  // Load hero stats on page load
  loadHeroStats();

  // Wire up the tab switcher for input mode
  document.querySelectorAll(".tab[data-tab]").forEach(tab => {
    tab.addEventListener("click", (e) => {
      e.preventDefault();
      switchInputTab(tab.dataset.tab);
    });
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
  document.getElementById("feedbackCorrectBtn")?.addEventListener("click", () => submitFeedback(true));
  document.getElementById("feedbackWrongBtn")?.addEventListener("click",   () => submitFeedback(false));

  // Remediation buttons
  document.getElementById("remediateQuarantineBtn")?.addEventListener("click", () => executeRemediation("quarantine"));
  document.getElementById("remediateBlockSenderBtn")?.addEventListener("click", () => executeRemediation("block_sender"));
  document.getElementById("remediateBlockUrlsBtn")?.addEventListener("click", () => executeRemediation("block_urls"));


  // ── Content Masking: auto-mask 1.5s after paste/type ──────────────────
  // Each maskable field also has a toggle button (#mask-<fieldId>)
  MASKABLE_FIELDS.forEach(fieldId => {
    const el = document.getElementById(fieldId);
    if (!el) return;

    // Auto-mask immediately on paste if content is substantive (> 20 chars)
    el.addEventListener("paste", () => {
      // Small delay to let the browser populate the value
      setTimeout(() => {
        if (el.value.length > 20) maskField(fieldId);
      }, 10);
    });

    // Also auto-mask when user leaves the field if it has content
    el.addEventListener("blur", () => {
      if (el.value.length > 20) maskField(fieldId);
    });

    // Wire the toggle button (lock icon beside each textarea)
    const btn = document.getElementById(`mask-${fieldId}`);
    if (btn) btn.addEventListener("click", () => toggleMask(fieldId));
  });
});

// ═══════════════════════════════════════════════════
//  INPUT TAB SWITCHING
// ═══════════════════════════════════════════════════
function switchInputTab(targetTab) {
  console.log(`[PhishGuard] Switching input tab to: ${targetTab}`);

  // Update tab button states
  document.querySelectorAll(".tab[data-tab]").forEach(btn => {
    const isActive = btn.dataset.tab === targetTab;
    btn.classList.toggle("active", isActive);
    btn.setAttribute("aria-selected", isActive.toString());
  });

  // Show/hide tab panels
  const panelFields = document.getElementById("panel-fields");
  const panelRaw    = document.getElementById("panel-raw");

  if (targetTab === "raw") {
    if (panelFields) {
      panelFields.hidden = true;
      panelFields.classList.remove("active");
    }
    if (panelRaw) {
      panelRaw.hidden = false;
      panelRaw.classList.add("active");
    }
  } else {
    if (panelFields) {
      panelFields.hidden = false;
      panelFields.classList.add("active");
    }
    if (panelRaw) {
      panelRaw.hidden = true;
      panelRaw.classList.remove("active");
    }
  }
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

  // Build payload — use getRealValue() so masked (●●●) fields send the real content.
  // Content fields are base64-encoded; _encrypted:true tells the server to decode them.
  const payload = isRawMode
    ? {
        _encrypted: true,
        raw_email:  b64Encode(getRealValue("inputRaw")),
        language:   lang,
      }
    : {
        _encrypted: true,
        sender:     b64Encode(document.getElementById("inputSender")?.value    || ""),
        recipient:  b64Encode(document.getElementById("inputRecipient")?.value || ""),
        subject:    b64Encode(document.getElementById("inputSubject")?.value   || ""),
        body_text:  b64Encode(getRealValue("inputBody")),
        language:   lang,
      };

  // ── Validation ──
  const mainContent = isRawMode ? getRealValue("inputRaw") : getRealValue("inputBody");

  if (!mainContent || mainContent.trim().length === 0) {
    showToast("Please enter email content to analyse. The field is empty.", "error");
    return;
  }

  // Improved validation: detect if content "looks" like an email vs random gibberish
  const validation = validateEmailContent(mainContent, isRawMode);
  if (!validation.isValid) {
    showToast(validation.message, "error");
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

  // ── 7. Toggle local remediation panel based on verdict ──
  const remediationPanel = document.getElementById("remediationPanel");
  if (remediationPanel) {
    remediationPanel.hidden = (clf !== "phishing");
  }

  // ── 8. Show results section with animation ──
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

  // Clear masked content store and reset all lock icons to unlocked
  MASKABLE_FIELDS.forEach(id => {
    delete _realContent[id];
    clearTimeout(_maskTimers[id]);
    _setMaskIcon(id, false);
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

  // Reset remediation panel and buttons
  const remPanel = document.getElementById("remediationPanel");
  if (remPanel) remPanel.hidden = true;

  const resetBtn = (id, html) => {
    const btn = document.getElementById(id);
    if (btn) {
      btn.removeAttribute("disabled");
      btn.innerHTML = html;
    }
  };
  resetBtn("remediateQuarantineBtn", `<i class="ti ti-box"></i>Quarantine Record`);
  resetBtn("remediateBlockSenderBtn", `<i class="ti ti-user-off"></i>Blacklist Sender`);
  resetBtn("remediateBlockUrlsBtn", `<i class="ti ti-link-off"></i>Blacklist Link Domains`);

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
//  REMEDIATION EXECUTION
// ═══════════════════════════════════════════════════
async function executeRemediation(action) {
  if (!currentAnalysisId) {
    showToast("No analysis available for remediation.", "error");
    return;
  }

  showToast("Executing remediation action...", "info");

  try {
    const res = await fetch("/api/v1/remediate", {
      method: "POST",
      headers: { "Content-Type": "application/json" },
      body: JSON.stringify({
        analysis_id: currentAnalysisId,
        action: action
      })
    });
    const data = await res.json();
    if (data.success) {
      showToast(data.message || "Remediation action completed.", "success");
      
      let btnId = "";
      if (action === "quarantine") btnId = "remediateQuarantineBtn";
      else if (action === "block_sender") btnId = "remediateBlockSenderBtn";
      else if (action === "block_urls") btnId = "remediateBlockUrlsBtn";

      const btn = document.getElementById(btnId);
      if (btn) {
        btn.setAttribute("disabled", "true");
        btn.innerHTML = `<i class="ti ti-check"></i> Applied`;
      }
    } else {
      showToast(data.error || "Action failed.", "error");
    }
  } catch (err) {
    showToast("Remediation execution failed.", "error");
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
