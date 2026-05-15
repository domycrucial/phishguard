"""
============================================================
backend/utils/pdf_exporter.py
PDF Report Generator for PhishGuard.
Uses WeasyPrint to render an HTML template to a PDF file.
The HTML template is built programmatically (no Jinja2 file
needed) to keep the system self-contained.
Output: saved to exports/ directory, returned as file path.
============================================================
"""

# Standard library imports
import os          # File path handling
import logging
from pathlib import Path
from typing import Dict, Any
from datetime import datetime

logger = logging.getLogger(__name__)   # Module-scoped logger

# --- WeasyPrint import (graceful fallback if not installed) ---
try:
    from weasyprint import HTML as WeasyHTML   # WeasyPrint HTML → PDF renderer
    WEASYPRINT_AVAILABLE = True
except ImportError:
    WEASYPRINT_AVAILABLE = False
    logger.warning("[PDFExporter] WeasyPrint not installed. PDF export disabled.")


def generate_pdf_report(report_data: Dict[str, Any], analysis_id: int, language: str = "en") -> Path:
    """
    Generate a PDF analysis report from report_data.

    Args:
        report_data: Dict containing analysis, email, triggered_rules, category_scores.
        analysis_id: The analysis ID (used in filename).
        language:    "en" or "sw" for report language.

    Returns:
        Path to the generated PDF file.

    Raises:
        RuntimeError if WeasyPrint is not installed.
        Exception on WeasyPrint rendering failure.
    """
    if not WEASYPRINT_AVAILABLE:
        raise RuntimeError(
            "WeasyPrint is not installed. Run: pip install weasyprint --break-system-packages"
        )

    # --- Build the HTML content for the report ---
    html_content = _build_report_html(report_data, language)

    # --- Determine output path ---
    from flask import current_app
    output_dir = current_app.config.get("PDF_OUTPUT_DIR", Path("exports"))
    output_path = Path(output_dir) / f"phishguard_report_{analysis_id}.pdf"

    # --- Render HTML to PDF using WeasyPrint ---
    WeasyHTML(string=html_content).write_pdf(str(output_path))
    logger.info(f"[PDFExporter] PDF generated: {output_path}")

    return output_path


def _build_report_html(data: Dict[str, Any], language: str) -> str:
    """
    Build a complete HTML document for the PDF report.
    All styles are inlined for WeasyPrint compatibility
    (WeasyPrint does not execute JavaScript and has limited CSS support).
    """
    analysis        = data["analysis"]
    email_row       = data["email"]
    triggered_rules = data.get("triggered_rules", [])
    category_scores = data.get("category_scores", {})

    # --- Determine colour based on classification ---
    clf = analysis.classification
    colour_map = {
        "phishing":   "#DC2626",   # Red
        "suspicious": "#F59E0B",   # Amber
        "legitimate": "#16A34A",   # Green
    }
    badge_colour = colour_map.get(clf, "#6B7280")   # Default grey

    # --- Labels (English / Swahili) ---
    labels = {
        "en": {
            "title":         "PhishGuard Analysis Report",
            "generated":     "Generated",
            "email_info":    "Email Information",
            "sender":        "Sender",
            "subject":       "Subject",
            "analysed_at":   "Analysed At",
            "risk_score":    "Risk Score",
            "classification":"Classification",
            "confidence":    "Confidence",
            "processing":    "Processing Time",
            "triggered":     "Triggered Rules",
            "category":      "Category Breakdown",
            "no_rules":      "No rules were triggered.",
            "risk_level":    "Risk Level",
            "ms":            "ms",
        },
        "sw": {
            "title":         "Ripoti ya Uchambuzi wa PhishGuard",
            "generated":     "Imetolewa",
            "email_info":    "Taarifa za Barua Pepe",
            "sender":        "Mtumaji",
            "subject":       "Kichwa cha Habari",
            "analysed_at":   "Imechambuliwa Saa",
            "risk_score":    "Alama ya Hatari",
            "classification":"Uainishaji",
            "confidence":    "Uhakika",
            "processing":    "Muda wa Uchakataji",
            "triggered":     "Sheria Zilizoanzishwa",
            "category":      "Mgawanyo wa Kategoria",
            "no_rules":      "Hakuna sheria zilizoanzishwa.",
            "risk_level":    "Kiwango cha Hatari",
            "ms":            "ms",
        }
    }
    L = labels.get(language, labels["en"])   # Pick language, fallback to English

    # --- Format triggered rules rows ---
    rules_rows_html = ""
    if triggered_rules:
        for tr, rule in triggered_rules:
            rules_rows_html += f"""
            <tr>
              <td style="padding:6px 8px; border:1px solid #e5e7eb; font-size:12px;">{rule.rule_id}</td>
              <td style="padding:6px 8px; border:1px solid #e5e7eb; font-size:12px;">{rule.name}</td>
              <td style="padding:6px 8px; border:1px solid #e5e7eb; font-size:12px;">{rule.category}</td>
              <td style="padding:6px 8px; border:1px solid #e5e7eb; font-size:12px; text-align:right;">{rule.weight}</td>
              <td style="padding:6px 8px; border:1px solid #e5e7eb; font-size:12px;">{tr.evidence or '-'}</td>
            </tr>"""
    else:
        rules_rows_html = f"""
        <tr><td colspan="5" style="padding:12px; text-align:center; color:#6B7280;">
          {L['no_rules']}
        </td></tr>"""

    # --- Format category scores ---
    cat_rows_html = ""
    for cat, score in sorted(category_scores.items(), key=lambda x: x[1], reverse=True):
        bar_width = int(min(100, score))
        cat_rows_html += f"""
        <tr>
          <td style="padding:5px 8px; font-size:12px; width:200px;">{cat.replace('_', ' ').title()}</td>
          <td style="padding:5px 8px;">
            <div style="background:#f3f4f6; border-radius:4px; height:12px; width:200px;">
              <div style="background:{badge_colour}; width:{bar_width}%; height:12px; border-radius:4px;"></div>
            </div>
          </td>
          <td style="padding:5px 8px; font-size:12px; font-weight:600;">{score:.1f}</td>
        </tr>"""

    # --- Assemble the full HTML document ---
    return f"""<!DOCTYPE html>
<html lang="{language}">
<head>
  <meta charset="UTF-8">
  <title>{L['title']}</title>
  <style>
    /* Base styles — WeasyPrint-compatible (no flexbox, limited CSS) */
    body       {{ font-family: Arial, sans-serif; font-size: 14px; color: #1f2937; margin: 0; padding: 0; }}
    .page      {{ max-width: 780px; margin: 30px auto; padding: 30px; }}
    .header    {{ background: #1e293b; color: white; padding: 24px 30px; margin: -30px -30px 24px -30px; }}
    .header h1 {{ margin: 0; font-size: 22px; }}
    .header p  {{ margin: 6px 0 0; font-size: 12px; color: #94a3b8; }}
    .badge     {{ display: inline-block; padding: 6px 18px; border-radius: 20px;
                  color: white; font-weight: bold; font-size: 16px; background: {badge_colour}; }}
    .section   {{ margin-bottom: 28px; }}
    .section h2{{ font-size: 15px; color: #374151; border-bottom: 2px solid #e5e7eb;
                  padding-bottom: 6px; margin-bottom: 14px; }}
    table      {{ width: 100%; border-collapse: collapse; }}
    th         {{ background: #f9fafb; padding: 8px; text-align: left;
                  font-size: 12px; border: 1px solid #e5e7eb; color: #374151; }}
    .score-box {{ background: #f9fafb; border: 2px solid {badge_colour};
                  border-radius: 8px; padding: 16px 24px; display: inline-block; margin: 8px 16px 8px 0; }}
    .score-box .num {{ font-size: 36px; font-weight: bold; color: {badge_colour}; }}
    .score-box .lbl {{ font-size: 11px; color: #6b7280; text-transform: uppercase; }}
    .footer    {{ margin-top: 40px; text-align: center; font-size: 11px; color: #9ca3af;
                  border-top: 1px solid #e5e7eb; padding-top: 12px; }}
  </style>
</head>
<body>
<div class="page">

  <!-- HEADER -->
  <div class="header">
    <h1>🛡 {L['title']}</h1>
    <p>{L['generated']}: {datetime.utcnow().strftime('%Y-%m-%d %H:%M UTC')}</p>
  </div>

  <!-- VERDICT -->
  <div class="section">
    <div class="score-box">
      <div class="num">{analysis.risk_score:.0f}</div>
      <div class="lbl">{L['risk_score']} / 100</div>
    </div>
    <div class="score-box">
      <div class="num">{int(analysis.confidence * 100)}%</div>
      <div class="lbl">{L['confidence']}</div>
    </div>
    <div class="score-box">
      <div class="num">{analysis.processing_time:.0f}</div>
      <div class="lbl">{L['processing']} ({L['ms']})</div>
    </div>
    <p style="margin-top:12px;">
      {L['classification']}: <span class="badge">{clf.upper()}</span>
    </p>
    <p style="color:#4b5563; font-size:13px;">{analysis.explanation or ''}</p>
  </div>

  <!-- EMAIL INFORMATION -->
  <div class="section">
    <h2>{L['email_info']}</h2>
    <table>
      <tr><th style="width:140px;">{L['sender']}</th><td style="padding:6px 8px; border:1px solid #e5e7eb;">{email_row.sender or 'N/A'}</td></tr>
      <tr><th>{L['subject']}</th><td style="padding:6px 8px; border:1px solid #e5e7eb;">{email_row.subject or 'N/A'}</td></tr>
      <tr><th>{L['analysed_at']}</th><td style="padding:6px 8px; border:1px solid #e5e7eb;">{analysis.analysed_at.strftime('%Y-%m-%d %H:%M UTC') if analysis.analysed_at else 'N/A'}</td></tr>
    </table>
  </div>

  <!-- TRIGGERED RULES -->
  <div class="section">
    <h2>{L['triggered']} ({len(triggered_rules)})</h2>
    <table>
      <tr>
        <th>ID</th><th>Name</th><th>Category</th><th>Weight</th><th>Evidence</th>
      </tr>
      {rules_rows_html}
    </table>
  </div>

  <!-- CATEGORY BREAKDOWN -->
  <div class="section">
    <h2>{L['category']}</h2>
    <table>{cat_rows_html}</table>
  </div>

  <!-- FOOTER -->
  <div class="footer">
    PhishGuard 2026· Analysis ID #{analysis.id} ·
    Phishing Email Detection System
  </div>

</div>
</body>
</html>"""
