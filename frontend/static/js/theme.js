/**
 * theme.js – Dark / Light Mode Toggle for PhishGuard.
 * Reads saved preference from localStorage on load.
 * Toggles data-theme="dark" on <html> element.
 * Updates the theme icon between moon (dark) and sun (light).
 */

// Read saved preference (default: light mode)
const savedTheme = localStorage.getItem("phishguard_theme") || "light";

/**
 * Apply a theme by setting data-theme on <html> and
 * updating the toggle button icon.
 * @param {string} theme - "light" or "dark"
 */
function applyTheme(theme) {
  document.documentElement.setAttribute("data-theme", theme);

  const icon = document.getElementById("themeIcon");
  if (icon) {
    // Sun icon = currently in dark mode (click to go light)
    // Moon icon = currently in light mode (click to go dark)
    icon.className = theme === "dark"
      ? "ti ti-sun"    // Show sun when in dark mode (click → light)
      : "ti ti-moon";  // Show moon when in light mode (click → dark)
  }

  const btn = document.getElementById("themeToggle");
  if (btn) {
    btn.setAttribute("aria-label", theme === "dark" ? "Switch to light mode" : "Switch to dark mode");
    btn.setAttribute("title", theme === "dark" ? "Switch to light mode" : "Switch to dark mode");
  }

  // Update Chart.js defaults if Chart is loaded (for dashboard charts)
  if (typeof Chart !== "undefined") {
    const textColor = theme === "dark" ? "#94A3B8" : "#4B5563";
    const gridColor = theme === "dark" ? "#334155" : "#E5E7EB";
    Chart.defaults.color         = textColor;
    Chart.defaults.borderColor   = gridColor;
  }
}

// Apply saved theme immediately (before DOM paints to avoid flash)
applyTheme(savedTheme);

// Wire up the toggle button once the DOM is ready
document.addEventListener("DOMContentLoaded", () => {
  const btn = document.getElementById("themeToggle");
  if (!btn) return;

  btn.addEventListener("click", () => {
    const current = document.documentElement.getAttribute("data-theme") || "light";
    const next    = current === "dark" ? "light" : "dark";   // Toggle between the two
    localStorage.setItem("phishguard_theme", next);          // Persist preference
    applyTheme(next);
  });
});
