/**
 * rules.js – PhishGuard Rule Management Page JavaScript.
 * Handles: loading rules, enable/disable toggles,
 * weight editing, custom rule creation modal.
 */

let allRules = [];   // Cached rules list for client-side filtering

document.addEventListener("DOMContentLoaded", () => {
  loadRules();

  // Search input (live filter)
  document.getElementById("ruleSearch")?.addEventListener("input", applyClientFilter);

  // Category + status dropdowns
  document.getElementById("ruleCategoryFilter")?.addEventListener("change", applyClientFilter);
  document.getElementById("ruleStatusFilter")?.addEventListener("change",   applyClientFilter);

  // Create rule modal open/close
  document.getElementById("openCreateRuleBtn")?.addEventListener("click",   () => openCreateModal());
  document.getElementById("closeCreateRuleBtn")?.addEventListener("click",  () => closeCreateModal());
  document.getElementById("cancelCreateRuleBtn")?.addEventListener("click", () => closeCreateModal());
  document.getElementById("submitCreateRuleBtn")?.addEventListener("click", submitCreateRule);

  // Edit modal close
  document.getElementById("closeEditRuleBtn")?.addEventListener("click",  () => closeEditModal());
  document.getElementById("cancelEditRuleBtn")?.addEventListener("click", () => closeEditModal());
  document.getElementById("saveEditRuleBtn")?.addEventListener("click",   saveEditRule);

  // Close modals on overlay click
  document.getElementById("createRuleModal")?.addEventListener("click", e => {
    if (e.target === document.getElementById("createRuleModal")) closeCreateModal();
  });
  document.getElementById("editRuleModal")?.addEventListener("click", e => {
    if (e.target === document.getElementById("editRuleModal")) closeEditModal();
  });
});

// ═══════════════════════════════════════════════════
//  LOAD RULES FROM API
// ═══════════════════════════════════════════════════
async function loadRules() {
  const tbody = document.getElementById("rulesTableBody");
  if (!tbody) return;
  tbody.innerHTML = `<tr><td colspan="7" class="table-empty"><i class="ti ti-loader ti-spin"></i> Loading rules…</td></tr>`;

  try {
    const res  = await fetch("/api/rules");
    const data = await res.json();

    if (!data.success) throw new Error("API error");

    allRules = data.rules;   // Cache for filtering
    renderRulesTable(allRules);
    updateRuleStats(allRules);

  } catch (err) {
    tbody.innerHTML = `<tr><td colspan="7" class="table-empty text-danger">Failed to load rules.</td></tr>`;
    console.error("[Rules] Load error:", err);
  }
}

// ═══════════════════════════════════════════════════
//  RENDER RULES TABLE
// ═══════════════════════════════════════════════════
function renderRulesTable(rules) {
  const tbody = document.getElementById("rulesTableBody");
  if (!tbody) return;

  if (!rules.length) {
    tbody.innerHTML = `<tr><td colspan="7" class="table-empty">No rules match the current filters.</td></tr>`;
    return;
  }

  tbody.innerHTML = rules.map(rule => {
    const catLabel  = formatCategory(rule.category);
    const typeLabel = rule.is_custom
      ? `<span class="badge badge-custom">Custom</span>`
      : `<span class="badge badge-info">System</span>`;

    return `
      <tr data-rule-id="${rule.id}">
        <td><code style="font-size:12px">${escHtml(rule.rule_id)}</code></td>
        <td style="max-width:260px">
          <div style="font-weight:500;font-size:13px">${escHtml(rule.name)}</div>
          <div style="font-size:11px;color:var(--text-muted);margin-top:2px">${escHtml(truncate(rule.description, 60))}</div>
        </td>
        <td><span class="badge badge-info">${escHtml(catLabel)}</span></td>
        <td>
          <span style="font-weight:600;color:${rule.weight >= 2.5 ? 'var(--color-danger)' : rule.weight >= 1.5 ? 'var(--color-warn)' : 'var(--color-brand)'}">${rule.weight}</span>
        </td>
        <td>
          <label class="toggle-switch" title="${rule.is_enabled ? 'Disable rule' : 'Enable rule'}">
            <input type="checkbox" ${rule.is_enabled ? "checked" : ""}
                   onchange="toggleRule(${rule.id}, this.checked)"
                   aria-label="Toggle rule ${escHtml(rule.rule_id)}" />
            <span class="toggle-slider"></span>
          </label>
        </td>
        <td>${typeLabel}</td>
        <td>
          <button class="btn btn-sm btn-outline" onclick="openEditModal(${rule.id})" title="Edit rule">
            <i class="ti ti-edit" aria-hidden="true"></i>
          </button>
        </td>
      </tr>`;
  }).join("");
}

// ═══════════════════════════════════════════════════
//  CLIENT-SIDE FILTER
// ═══════════════════════════════════════════════════
function applyClientFilter() {
  const search   = (document.getElementById("ruleSearch")?.value || "").toLowerCase();
  const category = document.getElementById("ruleCategoryFilter")?.value || "all";
  const status   = document.getElementById("ruleStatusFilter")?.value   || "all";

  let filtered = allRules;

  if (search) {
    filtered = filtered.filter(r =>
      r.name.toLowerCase().includes(search) ||
      r.rule_id.toLowerCase().includes(search) ||
      (r.description || "").toLowerCase().includes(search)
    );
  }

  if (category !== "all") {
    filtered = filtered.filter(r => r.category === category);
  }

  if (status === "true") {
    filtered = filtered.filter(r => r.is_enabled);
  } else if (status === "false") {
    filtered = filtered.filter(r => !r.is_enabled);
  }

  renderRulesTable(filtered);
}

// ═══════════════════════════════════════════════════
//  TOGGLE RULE ENABLE/DISABLE
// ═══════════════════════════════════════════════════
async function toggleRule(ruleDbId, enabled) {
  try {
    const res = await fetch(`/api/rules/${ruleDbId}`, {
      method:  "PATCH",
      headers: { "Content-Type": "application/json" },
      body:    JSON.stringify({ is_enabled: enabled }),
    });
    const data = await res.json();
    if (data.success) {
      // Update cached data
      const rule = allRules.find(r => r.id === ruleDbId);
      if (rule) rule.is_enabled = enabled;
      updateRuleStats(allRules);
      if (typeof showToast === "function") {
        showToast(`Rule ${data.rule_id} ${enabled ? "enabled" : "disabled"}.`, "success");
      }
    }
  } catch (err) {
    console.error("[Rules] Toggle error:", err);
    if (typeof showToast === "function") showToast("Failed to update rule.", "error");
    loadRules();   // Reload to revert optimistic UI
  }
}

// ═══════════════════════════════════════════════════
//  STATS COUNTER
// ═══════════════════════════════════════════════════
function updateRuleStats(rules) {
  document.getElementById("ruleTotal")?.textContent !== undefined &&
    (document.getElementById("ruleTotal").textContent    = rules.length);
  document.getElementById("ruleEnabled").textContent  = rules.filter(r => r.is_enabled).length;
  document.getElementById("ruleDisabled").textContent = rules.filter(r => !r.is_enabled).length;
  document.getElementById("ruleCustom").textContent   = rules.filter(r => r.is_custom).length;
}

// ═══════════════════════════════════════════════════
//  CREATE RULE MODAL
// ═══════════════════════════════════════════════════
function openCreateModal() {
  document.getElementById("createRuleModal").hidden = false;
  document.getElementById("createRuleError").hidden = true;
  // Clear fields
  ["newRuleName","newRuleCategory","newRulePattern","newRuleDesc"].forEach(id => {
    const el = document.getElementById(id);
    if (el) el.value = "";
  });
  document.getElementById("newRuleWeight").value = "1.5";
  document.getElementById("newRuleName")?.focus();
}

function closeCreateModal() {
  document.getElementById("createRuleModal").hidden = true;
}

async function submitCreateRule() {
  const errEl = document.getElementById("createRuleError");
  errEl.hidden = true;

  const payload = {
    name:        document.getElementById("newRuleName")?.value.trim(),
    category:    document.getElementById("newRuleCategory")?.value,
    weight:      parseFloat(document.getElementById("newRuleWeight")?.value),
    pattern:     document.getElementById("newRulePattern")?.value.trim(),
    description: document.getElementById("newRuleDesc")?.value.trim(),
  };

  try {
    const res  = await fetch("/api/rules", {
      method:  "POST",
      headers: { "Content-Type": "application/json" },
      body:    JSON.stringify(payload),
    });
    const data = await res.json();

    if (!data.success) {
      errEl.textContent = data.error || "Validation failed.";
      errEl.hidden = false;
      return;
    }

    closeCreateModal();
    if (typeof showToast === "function") showToast(`Rule ${data.rule_id} created!`, "success");
    loadRules();   // Reload to include new rule

  } catch (err) {
    errEl.textContent = "Server error. Please try again.";
    errEl.hidden = false;
  }
}

// ═══════════════════════════════════════════════════
//  EDIT RULE MODAL
// ═══════════════════════════════════════════════════
let editingRuleId = null;   // DB primary key of the rule being edited

function openEditModal(ruleDbId) {
  const rule = allRules.find(r => r.id === ruleDbId);
  if (!rule) return;

  editingRuleId = ruleDbId;
  const body = document.getElementById("editRuleBody");

  body.innerHTML = `
    <div class="form-group">
      <label class="form-label">Rule ID</label>
      <input class="form-input" value="${escHtml(rule.rule_id)}" disabled />
    </div>
    <div class="form-group">
      <label class="form-label">Name</label>
      <input class="form-input" value="${escHtml(rule.name)}" disabled />
    </div>
    <div class="form-group">
      <label class="form-label" for="editWeight">Weight (0.1 – 5.0)</label>
      <input type="number" id="editWeight" class="form-input" value="${rule.weight}" min="0.1" max="5.0" step="0.1" />
    </div>
    <div class="form-group">
      <label class="form-label" for="editDescription">Description</label>
      <textarea id="editDescription" class="form-textarea" rows="3">${escHtml(rule.description || "")}</textarea>
    </div>
    <div class="form-group">
      <label class="form-label">Status</label>
      <label class="toggle-switch">
        <input type="checkbox" id="editEnabled" ${rule.is_enabled ? "checked" : ""} />
        <span class="toggle-slider"></span>
      </label>
      <span style="font-size:13px;margin-left:8px;color:var(--text-secondary)">${rule.is_enabled ? "Enabled" : "Disabled"}</span>
    </div>`;

  document.getElementById("editRuleModal").hidden = false;
}

function closeEditModal() {
  document.getElementById("editRuleModal").hidden = true;
  editingRuleId = null;
}

async function saveEditRule() {
  if (!editingRuleId) return;

  const payload = {
    weight:      parseFloat(document.getElementById("editWeight")?.value),
    description: document.getElementById("editDescription")?.value.trim(),
    is_enabled:  document.getElementById("editEnabled")?.checked,
  };

  try {
    const res  = await fetch(`/api/rules/${editingRuleId}`, {
      method:  "PATCH",
      headers: { "Content-Type": "application/json" },
      body:    JSON.stringify(payload),
    });
    const data = await res.json();
    if (data.success) {
      closeEditModal();
      if (typeof showToast === "function") showToast("Rule updated successfully.", "success");
      loadRules();
    }
  } catch (err) {
    if (typeof showToast === "function") showToast("Failed to save changes.", "error");
  }
}

// ── Utilities ──
function formatCategory(cat) {
  return (cat || "").replace(/_/g, " ").replace(/\b\w/g, c => c.toUpperCase());
}
function truncate(str, max) { return str && str.length > max ? str.slice(0, max)+"…" : (str || ""); }
function escHtml(s) { return s ? String(s).replace(/&/g,"&amp;").replace(/</g,"&lt;").replace(/>/g,"&gt;") : ""; }
