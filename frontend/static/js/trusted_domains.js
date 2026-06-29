/**
 * trusted_domains.js – PhishGuard Whitelist Management Logic.
 * Handles fetching whitelisted domains from API, adding new domains,
 * filtering/searching domains, and deleting entries with visual feedback.
 */

let allDomains = [];

document.addEventListener("DOMContentLoaded", () => {
  fetchDomains();

  // Search input filter
  document.getElementById("domainSearch")?.addEventListener("input", e => {
    filterAndRender(e.target.value.trim().toLowerCase());
  });

  // Add domain form submit handler
  document.getElementById("addDomainForm")?.addEventListener("submit", async e => {
    e.preventDefault();
    const input = document.getElementById("domainInput");
    const domain = input.value.trim();

    if (!domain) return;

    try {
      const res = await fetch("/api/v1/trusted-domains", {
        method: "POST",
        headers: { "Content-Type": "application/json" },
        body: JSON.stringify({ domain })
      });
      const data = await res.json();

      if (data.success) {
        input.value = "";
        fetchDomains(); // Reload domains list
        showToast(`Domain '${domain}' whitelisted successfully.`);
      } else {
        alert(data.error || "Failed to add domain.");
      }
    } catch (err) {
      console.error("[TrustedDomains] Error adding domain:", err);
      alert("An error occurred. Make sure the server is running.");
    }
  });
});

// Fetch all trusted domains from API
async function fetchDomains() {
  try {
    const res = await fetch("/api/v1/trusted-domains");
    const data = await res.json();
    if (data.success) {
      allDomains = data.domains || [];
      filterAndRender("");
    }
  } catch (err) {
    console.error("[TrustedDomains] Error loading domains:", err);
  }
}

// Filter and render list
function filterAndRender(query) {
  const tbody = document.getElementById("domainsTableBody");
  const countEl = document.getElementById("domainCount");
  
  if (!tbody) return;

  const filtered = allDomains.filter(d => d.domain.includes(query));

  if (countEl) {
    countEl.textContent = `Total: ${filtered.length} domain(s)`;
  }

  if (filtered.length === 0) {
    tbody.innerHTML = `<tr><td colspan="3" style="text-align:center; padding:30px; color:var(--text-muted);">No domains found.</td></tr>`;
    return;
  }

  tbody.innerHTML = filtered.map(d => {
    const dateStr = d.created_at ? new Date(d.created_at).toLocaleDateString() : "—";
    return `
      <tr>
        <td style="font-weight:600; color:var(--text-main);">${escapeHtml(d.domain)}</td>
        <td class="text-muted">${dateStr}</td>
        <td style="text-align:right;">
          <button class="btn btn-outline-danger btn-sm" onclick="deleteDomain(${d.id}, '${escapeHtml(d.domain)}')" style="padding: 4px 8px;">
            <i class="ti ti-trash"></i> Delete
          </button>
        </td>
      </tr>
    `;
  }).join("");
}

// Delete domain handler
async function deleteDomain(id, domainName) {
  if (!confirm(`Are you sure you want to remove '${domainName}' from the trusted list?`)) return;

  try {
    const res = await fetch(`/api/v1/trusted-domains/${id}`, { method: "DELETE" });
    const data = await res.json();

    if (data.success) {
      fetchDomains(); // Reload domains list
      showToast(`Domain '${domainName}' removed from trusted list.`);
    } else {
      alert(data.error || "Failed to delete domain.");
    }
  } catch (err) {
    console.error("[TrustedDomains] Error deleting domain:", err);
  }
}

// Simple HTML escaping helper
function escapeHtml(str) {
  return str.replace(/&/g, "&amp;").replace(/</g, "&lt;").replace(/>/g, "&gt;").replace(/"/g, "&quot;");
}

// Simple temporary notification system
function showToast(msg) {
  const container = document.body;
  const toast = document.createElement("div");
  toast.style.position = "fixed";
  toast.style.bottom = "20px";
  toast.style.right = "20px";
  toast.style.backgroundColor = "var(--color-brand, #2563EB)";
  toast.style.color = "#FFF";
  toast.style.padding = "12px 24px";
  toast.style.borderRadius = "6px";
  toast.style.boxShadow = "0 4px 12px rgba(0,0,0,0.15)";
  toast.style.zIndex = "9999";
  toast.style.fontFamily = "sans-serif";
  toast.style.fontSize = "14px";
  toast.textContent = msg;

  container.appendChild(toast);
  setTimeout(() => {
    toast.style.transition = "opacity 0.5s ease";
    toast.style.opacity = "0";
    setTimeout(() => toast.remove(), 500);
  }, 3000);
}
