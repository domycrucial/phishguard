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
from datetime import datetime, timezone

logger = logging.getLogger(__name__)   # Module-scoped logger

# --- WeasyPrint import (graceful fallback if not installed/configured) ---
try:
    from weasyprint import HTML as WeasyHTML   # WeasyPrint HTML → PDF renderer
    WEASYPRINT_AVAILABLE = True
except Exception as exc:
    WEASYPRINT_AVAILABLE = False
    logger.warning(f"[PDFExporter] WeasyPrint could not be imported ({type(exc).__name__}: {exc}). falling back to fpdf2.")

# --- FPDF2 import (graceful fallback if not installed/configured) ---
try:
    from fpdf import FPDF
    FPDF_AVAILABLE = True
except Exception as exc:
    FPDF_AVAILABLE = False
    logger.warning(f"[PDFExporter] fpdf2 could not be imported ({type(exc).__name__}: {exc}). PDF export fallback disabled.")


def generate_pdf_report(report_data: Dict[str, Any], analysis_id: int, language: str = "en") -> Path:
    """
    Generate a PDF analysis report from report_data.

    Args:
        report_data: Dict containing analysis, email, triggered_rules, category_scores.
        analysis_id: The analysis ID (used in filename).
        language:    "en" or "sw" for report language.

    Returns:
        Path to the generated PDF file.
    """
    if WEASYPRINT_AVAILABLE:
        try:
            # --- Build the HTML content for the report ---
            html_content = _build_report_html(report_data, language)

            # --- Determine output path ---
            from flask import current_app
            output_dir = current_app.config.get("PDF_OUTPUT_DIR", Path("exports"))
            output_path = Path(output_dir) / f"phishguard_report_{analysis_id}.pdf"

            # --- Render HTML to PDF using WeasyPrint ---
            WeasyHTML(string=html_content).write_pdf(str(output_path))
            logger.info(f"[PDFExporter] PDF generated via WeasyPrint: {output_path}")
            return output_path
        except Exception as exc:
            logger.warning(f"[PDFExporter] WeasyPrint generation failed at runtime: {exc}. Trying fpdf2 fallback.")

    if FPDF_AVAILABLE:
        logger.info(f"[PDFExporter] Using fpdf2 fallback driver for analysis #{analysis_id}")
        return _generate_pdf_fallback_fpdf(report_data, analysis_id, language)
    else:
        raise RuntimeError(
            "Neither WeasyPrint nor fpdf2 are available. Unable to generate PDF."
        )



def clean_pdf_text(text: str) -> str:
    """
    Sanitise text for FPDF2 standard font usage (Helvetica).
    Replaces common emojis/Unicode symbols and strips characters that cannot be encoded in Latin-1.
    """
    if not text:
        return ""
    # Map common emojis/symbols to plain text equivalents
    mappings = {
        "⚠️": "WARNING: ",
        "⚠": "WARNING: ",
        "✓": "OK",
        "✔": "OK",
        "✗": "FAIL",
        "✘": "FAIL",
        "–": "-",  # en-dash
        "—": "-",  # em-dash
        "“": '"',
        "”": '"',
        "‘": "'",
        "’": "'",
    }
    for k, v in mappings.items():
        text = text.replace(k, v)

    # Filter out any other characters outside the Latin-1 range
    cleaned = []
    for char in text:
        try:
            char.encode('latin-1')
            cleaned.append(char)
        except UnicodeEncodeError:
            # Skip unrenderable character
            pass
    return "".join(cleaned)


def _generate_pdf_fallback_fpdf(data: Dict[str, Any], analysis_id: int, language: str) -> Path:
    """
    Generate a PDF report using fpdf2, completely bypassing HTML rendering engines.
    """
    from flask import current_app

    # Load labels
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
    L = labels.get(language, labels["en"])

    analysis        = data["analysis"]
    email_row       = data["email"]
    triggered_rules = data.get("triggered_rules", [])
    category_scores = data.get("category_scores", {})
    clf = analysis.classification

    # Colors
    color_map = {
        "phishing":   (220, 38, 38),   # Red
        "suspicious": (245, 158, 11),  # Amber
        "legitimate": (22, 163, 74),   # Green
    }
    badge_color = color_map.get(clf, (107, 114, 128))

    # Initialize FPDF
    pdf = FPDF()
    pdf.add_page()
    pdf.set_auto_page_break(auto=True, margin=15)

    # Title Header Banner
    pdf.set_fill_color(30, 41, 59) # #1e293b Dark Slate
    pdf.rect(0, 0, 210, 35, "F")

    pdf.set_text_color(255, 255, 255)
    pdf.set_font("Helvetica", "B", 18)
    pdf.set_xy(15, 8)
    pdf.cell(0, 10, L["title"], ln=True)

    pdf.set_font("Helvetica", "", 10)
    pdf.set_text_color(148, 163, 184) # light grey
    pdf.set_x(15)
    pdf.cell(0, 5, f"{L['generated']}: {datetime.now(timezone.utc).strftime('%Y-%m-%d %H:%M UTC')}", ln=True)

    # Content body styling
    pdf.set_text_color(31, 41, 55) # dark grey
    pdf.set_xy(15, 42)

    # Verdict boxes
    pdf.set_font("Helvetica", "B", 10)
    pdf.set_text_color(107, 114, 128)
    pdf.cell(60, 5, L["risk_score"].upper(), ln=False)
    pdf.cell(60, 5, L["confidence"].upper(), ln=False)
    pdf.cell(60, 5, L["processing"].upper(), ln=True)

    pdf.set_font("Helvetica", "B", 24)
    # Set text color based on classification
    pdf.set_text_color(*badge_color)
    pdf.cell(60, 10, f"{analysis.risk_score:.0f} / 100", ln=False)
    pdf.cell(60, 10, f"{int(analysis.confidence * 100)}%", ln=False)
    pdf.cell(60, 10, f"{analysis.processing_time:.0f} {L['ms']}", ln=True)

    pdf.ln(4)
    # Classification Badge
    pdf.set_font("Helvetica", "B", 12)
    pdf.set_text_color(31, 41, 55)
    pdf.cell(35, 8, f"{L['classification']}: ", ln=False)
    pdf.set_text_color(255, 255, 255)
    
    # Draw colored rectangle for classification badge
    x, y = pdf.get_x(), pdf.get_y()
    pdf.set_fill_color(*badge_color)
    # Measure width
    text_w = pdf.get_string_width(clf.upper()) + 6
    pdf.rect(x, y + 1, text_w, 6, "F")
    pdf.set_xy(x + 3, y)
    pdf.cell(text_w, 8, clf.upper(), ln=True)

    pdf.ln(3)
    # Explanation Narrative block
    pdf.set_font("Helvetica", "", 10)
    pdf.set_text_color(75, 85, 99)
    pdf.multi_cell(0, 5, clean_pdf_text(analysis.explanation or ""))
    pdf.ln(5)

    # Email Info Section
    pdf.set_font("Helvetica", "B", 12)
    pdf.set_text_color(55, 65, 81)
    pdf.cell(0, 8, L["email_info"], border="B", ln=True)
    pdf.ln(2)

    pdf.set_font("Helvetica", "", 10)
    # Draw email metadata grid
    pdf.set_fill_color(249, 250, 251)

    # Sender Row
    pdf.set_font("Helvetica", "B", 10)
    pdf.cell(40, 7, L["sender"], border=1, fill=True)
    pdf.set_font("Helvetica", "", 10)
    pdf.cell(0, 7, clean_pdf_text(email_row.sender or "N/A"), border=1, ln=True)

    # Subject Row
    pdf.set_font("Helvetica", "B", 10)
    pdf.cell(40, 7, L["subject"], border=1, fill=True)
    pdf.set_font("Helvetica", "", 10)
    pdf.cell(0, 7, clean_pdf_text(email_row.subject or "N/A"), border=1, ln=True)

    # Analysed At Row
    pdf.set_font("Helvetica", "B", 10)
    pdf.cell(40, 7, L["analysed_at"], border=1, fill=True)
    pdf.set_font("Helvetica", "", 10)
    analysed_str = analysis.analysed_at.strftime('%Y-%m-%d %H:%M UTC') if analysis.analysed_at else 'N/A'
    pdf.cell(0, 7, analysed_str, border=1, ln=True)
    pdf.ln(5)

    # Triggered Rules Section
    pdf.set_font("Helvetica", "B", 12)
    pdf.cell(0, 8, f"{L['triggered']} ({len(triggered_rules)})", border="B", ln=True)
    pdf.ln(2)

    # Rules Table headers
    pdf.set_font("Helvetica", "B", 9)
    pdf.set_fill_color(249, 250, 251)
    pdf.cell(20, 7, "ID", border=1, fill=True)
    pdf.cell(55, 7, "Name", border=1, fill=True)
    pdf.cell(45, 7, "Category", border=1, fill=True)
    pdf.cell(15, 7, "Weight", border=1, fill=True, align="C")
    pdf.cell(45, 7, "Evidence", border=1, fill=True, ln=True)

    pdf.set_font("Helvetica", "", 8)
    if triggered_rules:
        for tr, rule in triggered_rules:
            # We want to support multi-line wrap for long rule names or evidence
            name_truncated = rule.name[:32] + "..." if len(rule.name) > 35 else rule.name
            pdf.cell(20, 7, clean_pdf_text(str(rule.rule_id)), border=1)
            pdf.cell(55, 7, clean_pdf_text(name_truncated), border=1)
            pdf.cell(45, 7, clean_pdf_text(str(rule.category)), border=1)
            pdf.cell(15, 7, f"{rule.weight:.1f}", border=1, align="C")
            
            evidence_truncated = (tr.evidence[:25] + "...") if tr.evidence and len(tr.evidence) > 28 else (tr.evidence or "-")
            pdf.cell(45, 7, clean_pdf_text(evidence_truncated), border=1, ln=True)
    else:
        pdf.cell(0, 10, L["no_rules"], border=1, align="C", ln=True)
    pdf.ln(5)

    # Category Breakdown Section
    pdf.set_font("Helvetica", "B", 12)
    pdf.cell(0, 8, L["category"], border="B", ln=True)
    pdf.ln(2)

    pdf.set_font("Helvetica", "", 10)
    for cat, score in sorted(category_scores.items(), key=lambda x: x[1], reverse=True):
        cat_title = cat.replace('_', ' ').title()
        pdf.cell(50, 6, cat_title, border=0)

        # Simple text representation of progress bar
        bar_len = int(min(20, score / 5))
        bar_str = "[" + "=" * bar_len + " " * (20 - bar_len) + "]"
        pdf.set_font("Courier", "", 10)
        pdf.cell(60, 6, bar_str, border=0)

        pdf.set_font("Helvetica", "B", 10)
        pdf.cell(20, 6, f"{score:.1f}", border=0, ln=True)

    pdf.ln(10)
    # Footer
    pdf.set_font("Helvetica", "I", 8)
    pdf.set_text_color(156, 163, 175)
    pdf.cell(0, 10, f"PhishGuard 2026  Analysis ID #{analysis.id}  Phishing Email Detection System", align="C")

    # Output file
    output_dir = current_app.config.get("PDF_OUTPUT_DIR", Path("exports"))
    output_path = Path(output_dir) / f"phishguard_report_{analysis_id}.pdf"
    pdf.output(name=str(output_path))

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
    <p>{L['generated']}: {datetime.now(timezone.utc).strftime('%Y-%m-%d %H:%M UTC')}</p>
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
