/**
 * history.js – Load the 5 most recent analyses for the index page history strip.
 */
document.addEventListener("DOMContentLoaded", async () => {
  const tbody = document.getElementById("historyBody");
  if (!tbody) return;   // Not on the index page

  try {
    const res  = await fetch("/api/v1/history?page=1&per_page=5");
    const data = await res.json();

    if (!data.success || !data.items.length) {
      tbody.innerHTML = `<tr><td colspan="5" class="table-empty">No analyses yet. Submit your first email above!</td></tr>`;
      return;
    }

    tbody.innerHTML = data.items.map(item => {
      const scoreClass = item.risk_score >= 60 ? "score-high"
                       : item.risk_score >= 30 ? "score-medium"
                       : "score-low";
      const clfClass = `clf-${item.classification}`;
      const timeAgo  = getTimeAgo(item.analysed_at);

      return `
        <tr>
          <td>${escHtml(truncate(item.sender, 28))}</td>
          <td>${escHtml(truncate(item.subject, 36))}</td>
          <td><span class="score-pill ${scoreClass}">${item.risk_score}</span></td>
          <td><span class="clf-badge ${clfClass}">${item.classification}</span></td>
          <td style="color:var(--text-muted);font-size:12px">${timeAgo}</td>
        </tr>`;
    }).join("");

  } catch (_) {
    // Silently fail for the history strip
  }
});

function getTimeAgo(isoString) {
  if (!isoString) return "—";
  const diff = (Date.now() - new Date(isoString)) / 1000;   // Seconds ago
  if (diff < 60)   return "Just now";
  if (diff < 3600) return `${Math.floor(diff/60)}m ago`;
  if (diff < 86400) return `${Math.floor(diff/3600)}h ago`;
  return `${Math.floor(diff/86400)}d ago`;
}

function truncate(str, max) { if (!str) return "—"; return str.length > max ? str.slice(0, max)+"…" : str; }
function escHtml(s) { return s ? String(s).replace(/&/g,"&amp;").replace(/</g,"&lt;").replace(/>/g,"&gt;") : ""; }
