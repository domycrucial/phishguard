/**
 * training.js – PhishGuard Training Mode JavaScript.
 * Loads sample emails, renders training cards,
 * handles challenge modal, scoring, and hints.
 */

// Training score state (persisted in sessionStorage)
let scoreCorrect = parseInt(sessionStorage.getItem("pg_correct") || "0");
let scoreWrong   = parseInt(sessionStorage.getItem("pg_wrong")   || "0");

let currentSample    = null;   // The sample currently shown in the modal
let selectedChoice   = null;   // The choice the user selected

// ─── Initialise ───────────────────────────────────
document.addEventListener("DOMContentLoaded", () => {
  updateScoreDisplay();
  loadTrainingSamples("all");

  // Filter pills
  document.querySelectorAll(".filter-pill[data-filter]").forEach(pill => {
    pill.addEventListener("click", () => {
      document.querySelectorAll(".filter-pill").forEach(p => p.classList.remove("active"));
      pill.classList.add("active");
      loadTrainingSamples(pill.dataset.filter);
    });
  });

  // Reset score
  document.getElementById("resetScoreBtn")?.addEventListener("click", resetScore);

  // Modal close buttons
  document.getElementById("modalClose")?.addEventListener("click", closeModal);
  document.getElementById("modalOverlay")?.addEventListener("click", e => {
    if (e.target === document.getElementById("modalOverlay")) closeModal();
  });

  // Choice buttons in modal
  document.querySelectorAll(".choice-btn").forEach(btn => {
    btn.addEventListener("click", () => selectChoice(btn.dataset.choice));
  });

  // Submit answer
  document.getElementById("submitChoiceBtn")?.addEventListener("click", submitAnswer);

  // "Analyse in PhishGuard" button
  document.getElementById("analyseThisBtn")?.addEventListener("click", analyseCurrentSample);
});

// ═══════════════════════════════════════════════════
//  LOAD TRAINING SAMPLES
// ═══════════════════════════════════════════════════
async function loadTrainingSamples(type) {
  const grid = document.getElementById("trainingGrid");
  if (!grid) return;

  grid.innerHTML = `<div class="training-loading"><i class="ti ti-loader ti-spin"></i> Loading samples…</div>`;

  try {
    const url  = `/api/v1/training?type=${encodeURIComponent(type)}`;
    const res  = await fetch(url);
    const data = await res.json();

    if (!data.success || !data.samples.length) {
      grid.innerHTML = `<div class="training-loading">No samples found for this filter.</div>`;
      return;
    }

    grid.innerHTML = "";
    data.samples.forEach(sample => renderTrainingCard(sample, grid));

  } catch (err) {
    grid.innerHTML = `<div class="training-loading" style="color:var(--color-danger)">Failed to load samples.</div>`;
    console.error("[Training] Load error:", err);
  }
}

// ═══════════════════════════════════════════════════
//  RENDER TRAINING CARD
// ═══════════════════════════════════════════════════
function renderTrainingCard(sample, container) {
  const card = document.createElement("div");
  card.className = "training-card";
  card.setAttribute("role", "listitem");
  card.setAttribute("tabindex", "0");
  card.setAttribute("aria-label", `Training sample: ${sample.title}`);
  card.dataset.id = sample.id;

  const diffClass = { easy: "diff-easy", medium: "diff-medium", hard: "diff-hard" };

  // Body text preview (first 100 chars)
  const preview = (sample.body_text || "").slice(0, 100).trim();

  card.innerHTML = `
    <div class="training-card-header">
      <h3 class="training-title">${escHtml(sample.title)}</h3>
      <span class="difficulty-badge ${diffClass[sample.difficulty] || "diff-medium"}">
        ${sample.difficulty?.toUpperCase() || "MEDIUM"}
      </span>
    </div>
    <div class="training-meta">
      <i class="ti ti-mail" aria-hidden="true"></i> ${escHtml(truncate(sample.sender, 40))}
    </div>
    <div class="training-preview">${escHtml(preview)}…</div>
    <div style="margin-top:10px;display:flex;justify-content:flex-end">
      <span class="btn btn-sm btn-outline">
        <i class="ti ti-eye" aria-hidden="true"></i> View Challenge
      </span>
    </div>`;

  // Click or Enter to open modal
  const openModal = () => openChallengeModal(sample);
  card.addEventListener("click", openModal);
  card.addEventListener("keydown", e => {
    if (e.key === "Enter" || e.key === " ") { e.preventDefault(); openModal(); }
  });

  container.appendChild(card);
}

// ═══════════════════════════════════════════════════
//  CHALLENGE MODAL
// ═══════════════════════════════════════════════════
function openChallengeModal(sample) {
  currentSample  = sample;
  selectedChoice = null;

  const overlay = document.getElementById("modalOverlay");
  const body    = document.getElementById("modalBody");

  // Reset modal state
  document.querySelectorAll(".choice-btn").forEach(b => b.classList.remove("selected"));
  document.getElementById("submitChoiceBtn").disabled = true;
  document.getElementById("hintSection").hidden = true;

  // Populate email display
  body.innerHTML = `
    <div style="background:var(--bg-input);border:1px solid var(--border-color);border-radius:var(--radius-md);padding:16px;margin-bottom:12px">
      <div style="margin-bottom:6px;font-size:13px">
        <strong>From:</strong> <span style="color:var(--text-secondary)">${escHtml(sample.sender)}</span>
      </div>
      <div style="margin-bottom:6px;font-size:13px">
        <strong>Subject:</strong> <span style="color:var(--text-secondary)">${escHtml(sample.subject)}</span>
      </div>
      <hr style="border:none;border-top:1px solid var(--border-color);margin:10px 0">
      <div style="font-size:13px;color:var(--text-primary);white-space:pre-wrap;line-height:1.7">${escHtml(sample.body_text)}</div>
    </div>`;

  // Set modal title with difficulty
  document.getElementById("modalTitle").textContent = sample.title;

  overlay.hidden = false;
  overlay.focus();   // Move focus into modal for accessibility
}

function closeModal() {
  const overlay = document.getElementById("modalOverlay");
  overlay.hidden = true;
  currentSample  = null;
  selectedChoice = null;
}

// ═══════════════════════════════════════════════════
//  CHOICE SELECTION
// ═══════════════════════════════════════════════════
function selectChoice(choice) {
  selectedChoice = choice;

  // Update button visual states
  document.querySelectorAll(".choice-btn").forEach(btn => {
    btn.classList.toggle("selected", btn.dataset.choice === choice);
  });

  // Enable submit button once a choice is selected
  document.getElementById("submitChoiceBtn").disabled = false;
}

// ═══════════════════════════════════════════════════
//  SUBMIT ANSWER
// ═══════════════════════════════════════════════════
function submitAnswer() {
  if (!selectedChoice || !currentSample) return;

  const isCorrect = selectedChoice === currentSample.expected_type;

  // Update score
  if (isCorrect) {
    scoreCorrect++;
    sessionStorage.setItem("pg_correct", scoreCorrect);
  } else {
    scoreWrong++;
    sessionStorage.setItem("pg_wrong", scoreWrong);
  }
  updateScoreDisplay();

  // Show hint section
  const hintSection = document.getElementById("hintSection");
  const hintResult  = document.getElementById("hintResult");
  const hintText    = document.getElementById("hintText");
  const hintList    = document.getElementById("hintIndicators");

  hintResult.className = `hint-result ${isCorrect ? "hint-correct" : "hint-wrong"}`;
  hintResult.innerHTML = isCorrect
    ? `✅ Correct! This is a <strong>${currentSample.expected_type}</strong> email.`
    : `❌ Incorrect. This is actually a <strong>${currentSample.expected_type}</strong> email.`;

  hintText.textContent = currentSample.hint || "No hint available.";

  // Render key indicators list
  const indicators = currentSample.key_indicators || [];
  hintList.innerHTML = indicators.map(ind => `<li>${escHtml(ind)}</li>`).join("");

  hintSection.hidden = false;

  // Disable choice buttons after submission
  document.querySelectorAll(".choice-btn").forEach(b => b.disabled = true);
  document.getElementById("submitChoiceBtn").disabled = true;

  // Mark the training card in the grid
  const card = document.querySelector(`.training-card[data-id="${currentSample.id}"]`);
  if (card) {
    card.classList.add(isCorrect ? "answered-correct" : "answered-wrong");
  }
}

// ═══════════════════════════════════════════════════
//  "ANALYSE IN PHISHGUARD" BUTTON
// ═══════════════════════════════════════════════════
function analyseCurrentSample() {
  if (!currentSample) return;
  // Store sample in sessionStorage for the main page to pick up
  sessionStorage.setItem("pg_prefill", JSON.stringify({
    sender:    currentSample.sender,
    subject:   currentSample.subject,
    body_text: currentSample.body_text,
  }));
  closeModal();
  window.location.href = "/";   // Navigate to the analysis page
}

// ═══════════════════════════════════════════════════
//  SCORE DISPLAY
// ═══════════════════════════════════════════════════
function updateScoreDisplay() {
  document.getElementById("scoreCorrect").textContent = scoreCorrect;
  document.getElementById("scoreWrong").textContent   = scoreWrong;
  const total    = scoreCorrect + scoreWrong;
  const accuracy = total > 0 ? Math.round((scoreCorrect / total) * 100) + "%" : "—";
  document.getElementById("scoreAccuracy").textContent = accuracy;
}

function resetScore() {
  scoreCorrect = 0;
  scoreWrong   = 0;
  sessionStorage.removeItem("pg_correct");
  sessionStorage.removeItem("pg_wrong");
  updateScoreDisplay();
  // Remove answered states from all cards
  document.querySelectorAll(".training-card").forEach(c => {
    c.classList.remove("answered-correct", "answered-wrong");
  });
  if (typeof showToast === "function") showToast("Score reset!", "info");
}

// ── Utilities ──
function truncate(str, max) { return str && str.length > max ? str.slice(0, max)+"…" : (str || "—"); }
function escHtml(s) { return s ? String(s).replace(/&/g,"&amp;").replace(/</g,"&lt;").replace(/>/g,"&gt;") : ""; }

// ─── Pre-fill from training page (if user clicked "Analyse") ───
document.addEventListener("DOMContentLoaded", () => {
  const prefill = sessionStorage.getItem("pg_prefill");
  if (prefill) {
    try {
      const data = JSON.parse(prefill);
      if (document.getElementById("inputSender"))  document.getElementById("inputSender").value  = data.sender  || "";
      if (document.getElementById("inputSubject")) document.getElementById("inputSubject").value = data.subject || "";
      if (document.getElementById("inputBody"))    document.getElementById("inputBody").value    = data.body_text || "";
      sessionStorage.removeItem("pg_prefill");   // Clear after use
    } catch (_) {}
  }
});
