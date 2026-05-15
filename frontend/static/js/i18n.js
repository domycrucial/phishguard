/**
 * i18n.js – Internationalisation (EN / SW) for PhishGuard frontend.
 * Reads data-i18n attributes on DOM elements and replaces their
 * textContent with the translation for the active language.
 * Language preference is persisted in localStorage.
 */

// Translation strings for English and Swahili
const TRANSLATIONS = {
  en: {
    // Navbar
    nav_analyse:    "Analyse",
    nav_dashboard:  "Dashboard",
    nav_training:   "Training",
    nav_rules:      "Rules",

    // Hero
    hero_title:    "Detect Phishing Emails Instantly",
    hero_subtitle: "Paste any email content below — our AI-powered rule engine analyses 30+ threat indicators in under 2 seconds.",
    stat_analysed:  "analysed",
    stat_phishing:  "phishing",
    stat_suspicious:"suspicious",

    // Input form
    input_title:    "Email Input",
    tab_fields:     "Form Fields",
    tab_raw:        "Raw Email",
    lbl_sender:     "From (Sender)",
    lbl_recipient:  "To (Recipient)",
    lbl_subject:    "Subject",
    lbl_body:       "Email Body (Plain Text)",
    lbl_html:       "HTML Body (optional)",
    lbl_headers:    "Email Headers (optional)",
    lbl_raw:        "Full RFC-2822 Email",
    lbl_report_lang:"Report Language:",
    btn_analyse:    "Analyse Email",
    btn_clear:      "Clear",
    progress_parsing:"Parsing email…",

    // Result tabs
    rtab_rules:      "Triggered Rules",
    rtab_categories: "Category Breakdown",
    rtab_info:       "Email Info",
    rules_fired:     "rules",

    // Buttons
    btn_export:   "Export PDF",
    btn_correct:  "Correct",
    btn_wrong:    "Incorrect",
    btn_new:      "New Analysis",

    // History
    recent_history: "Recent Analyses",
    view_all:       "View all",
    th_sender:      "Sender",
    th_subject:     "Subject",
    th_score:       "Score",
    th_class:       "Classification",
    th_time:        "Time",
    th_confidence:  "Confidence",
    th_date:        "Date",
    th_export:      "Export",

    // Dashboard
    dash_title:           "Analytics Dashboard",
    dash_subtitle:        "Overview of all phishing detection activity",
    btn_refresh:          "Refresh",
    stat_total:           "Total Analysed",
    stat_phishing_count:  "Phishing",
    stat_suspicious_count:"Suspicious",
    stat_legitimate_count:"Legitimate",
    stat_avg_score:       "Avg. Risk Score",
    chart_trend:          "14-Day Trend",
    chart_breakdown:      "Classification Split",
    top_rules_title:      "Top Triggered Rules (Heatmap)",
    full_history:         "Analysis History",
    filter_label:         "Filter:",
    filter_all:           "All",
    filter_phishing:      "Phishing",
    filter_suspicious:    "Suspicious",
    filter_legitimate:    "Legitimate",
    btn_prev:             "Prev",
    btn_next:             "Next",

    // Classifications
    phishing:   "Phishing",
    suspicious: "Suspicious",
    legitimate: "Legitimate",
  },

  sw: {
    // Navbar
    nav_analyse:    "Changanua",
    nav_dashboard:  "Dashibodi",
    nav_training:   "Mafunzo",
    nav_rules:      "Sheria",

    // Hero
    hero_title:    "Gundua Barua Pepe za Udanganyifu Papo Hapo",
    hero_subtitle: "Bandika maudhui ya barua pepe hapa chini — injini yetu ya sheria inachunguza dalili 30+ za vitisho kwa chini ya sekunde 2.",
    stat_analysed:  "zimechambuliwa",
    stat_phishing:  "udanganyifu",
    stat_suspicious:"inashuku",

    // Input form
    input_title:    "Ingiza Barua Pepe",
    tab_fields:     "Sehemu za Fomu",
    tab_raw:        "Barua Pepe Kamili",
    lbl_sender:     "Kutoka (Mtumaji)",
    lbl_recipient:  "Kwenda (Mpokeaji)",
    lbl_subject:    "Mada",
    lbl_body:       "Maudhui ya Barua Pepe",
    lbl_html:       "Maudhui ya HTML (si lazima)",
    lbl_headers:    "Vichwa vya Barua Pepe (si lazima)",
    lbl_raw:        "Barua Pepe Kamili RFC-2822",
    lbl_report_lang:"Lugha ya Ripoti:",
    btn_analyse:    "Changanua Barua Pepe",
    btn_clear:      "Futa",
    progress_parsing:"Inasoma barua pepe…",

    // Result tabs
    rtab_rules:      "Sheria Zilizoanzishwa",
    rtab_categories: "Mgawanyo wa Kategoria",
    rtab_info:       "Taarifa za Barua Pepe",
    rules_fired:     "sheria",

    // Buttons
    btn_export:   "Hamisha PDF",
    btn_correct:  "Sahihi",
    btn_wrong:    "Si Sahihi",
    btn_new:      "Uchambuzi Mpya",

    // History
    recent_history: "Uchambuzi wa Hivi Karibuni",
    view_all:       "Tazama zote",
    th_sender:      "Mtumaji",
    th_subject:     "Mada",
    th_score:       "Alama",
    th_class:       "Uainishaji",
    th_time:        "Muda",
    th_confidence:  "Uhakika",
    th_date:        "Tarehe",
    th_export:      "Hamisha",

    // Dashboard
    dash_title:           "Dashibodi ya Takwimu",
    dash_subtitle:        "Muhtasari wa shughuli zote za kugundua udanganyifu",
    btn_refresh:          "Onyesha Upya",
    stat_total:           "Jumla Zilizochambuliwa",
    stat_phishing_count:  "Udanganyifu",
    stat_suspicious_count:"Zinashuku",
    stat_legitimate_count:"Halali",
    stat_avg_score:       "Wastani wa Alama za Hatari",
    chart_trend:          "Mwelekeo wa Siku 14",
    chart_breakdown:      "Mgawanyo wa Uainishaji",
    top_rules_title:      "Sheria Zinazoanzishwa Zaidi",
    full_history:         "Historia ya Uchambuzi",
    filter_label:         "Chuja:",
    filter_all:           "Zote",
    filter_phishing:      "Udanganyifu",
    filter_suspicious:    "Zinashuku",
    filter_legitimate:    "Halali",
    btn_prev:             "Iliyotangulia",
    btn_next:             "Inayofuata",

    // Classifications
    phishing:   "Udanganyifu",
    suspicious: "Inashuku",
    legitimate: "Halali",
  }
};

// Currently active language code
let currentLang = localStorage.getItem("phishguard_lang") || "en";

/**
 * Apply translations to all elements with data-i18n attributes.
 * Called on page load and when language switches.
 */
function applyTranslations() {
  const dict = TRANSLATIONS[currentLang] || TRANSLATIONS["en"];   // Fallback to English

  // Find every element with data-i18n attribute
  document.querySelectorAll("[data-i18n]").forEach(el => {
    const key  = el.getAttribute("data-i18n");   // e.g. "btn_analyse"
    const text = dict[key];                       // Look up the translation
    if (text !== undefined) {
      el.textContent = text;   // Replace the element's text
    }
  });

  // Update lang switcher button states
  document.querySelectorAll(".lang-btn").forEach(btn => {
    const isActive = btn.dataset.lang === currentLang;
    btn.classList.toggle("active", isActive);
    btn.setAttribute("aria-pressed", isActive.toString());
  });

  // Update the <html> lang attribute for screen readers
  document.documentElement.setAttribute("lang", currentLang);
}

/**
 * Get a translated string by key (for use in JS-injected HTML).
 * @param {string} key - Translation key
 * @returns {string} Translated string or the key itself as fallback
 */
function t(key) {
  const dict = TRANSLATIONS[currentLang] || TRANSLATIONS["en"];
  return dict[key] || key;   // Return key itself if translation missing
}

/**
 * Switch the active language and re-apply all translations.
 * @param {string} lang - Language code: "en" or "sw"
 */
function setLanguage(lang) {
  if (!TRANSLATIONS[lang]) return;   // Ignore unknown language codes
  currentLang = lang;
  localStorage.setItem("phishguard_lang", lang);   // Persist preference
  applyTranslations();
}

// Wire up language switcher buttons
document.querySelectorAll(".lang-btn").forEach(btn => {
  btn.addEventListener("click", () => setLanguage(btn.dataset.lang));
});

// Apply translations immediately on script load
applyTranslations();

// Export for use by other modules (non-module scripts use globals)
window.t = t;
window.setLanguage = setLanguage;
window.currentLang = () => currentLang;
