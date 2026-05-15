/**
 * sidebar.js – Handles hamburger open/close, overlay, stats loader
 * for all 4 pages. Loaded on every page.
 */
document.addEventListener("DOMContentLoaded", () => {
  const sidebar  = document.getElementById("sidebar");
  const overlay  = document.getElementById("sidebarOverlay");
  const hamburger= document.getElementById("hamburger");
  const topbarTheme   = document.getElementById("topbarTheme");
  const topbarThemeIcon = document.getElementById("topbarThemeIcon");

  // Open/close sidebar on mobile
  if (hamburger) {
    hamburger.addEventListener("click", () => {
      sidebar.classList.toggle("open");
      overlay.classList.toggle("active");
    });
  }
  if (overlay) {
    overlay.addEventListener("click", () => {
      sidebar.classList.remove("open");
      overlay.classList.remove("active");
    });
  }

  // Topbar theme button (mobile) mirrors the sidebar button
  if (topbarTheme) {
    topbarTheme.addEventListener("click", () => {
      const current = document.documentElement.getAttribute("data-theme") || "light";
      const next = current === "dark" ? "light" : "dark";
      localStorage.setItem("phishguard_theme", next);
      // reuse the applyTheme function from theme.js
      if (typeof applyTheme === "function") applyTheme(next);
    });
  }

  // Sync topbar lang buttons
  document.querySelectorAll(".topbar-lang-btn").forEach(btn => {
    btn.addEventListener("click", () => {
      if (typeof setLanguage === "function") setLanguage(btn.dataset.lang);
      document.querySelectorAll(".topbar-lang-btn").forEach(b =>
        b.classList.toggle("active", b.dataset.lang === btn.dataset.lang));
    });
  });

  // Load live sidebar stats
  loadSidebarStats();
});

async function loadSidebarStats() {
  try {
    const res  = await fetch("/api/stats");
    const data = await res.json();
    if (!data.success) return;
    const set = (id, val) => { const el = document.getElementById(id); if(el) el.textContent = val; };
    set("sidebarTotal",     data.total);
    set("sidebarPhishing",  data.phishing);
    set("sidebarSuspicious",data.suspicious);
    set("sidebarLegitimate",data.legitimate);
  } catch (_) {}
}
