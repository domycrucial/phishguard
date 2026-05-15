"""
============================================================
backend/api/routes.py
REST API Routes for PhishGuard.
Endpoints:
  POST /api/analyse        – Run analysis on submitted email
  GET  /api/history        – Paginated analysis history
  GET  /api/stats          – Aggregated statistics for dashboard
  GET  /api/rules          – List all rules
  POST /api/rules          – Create a custom rule
  PATCH /api/rules/<id>    – Update/toggle a rule
  GET  /api/export/<id>    – Export analysis as PDF
  POST /api/feedback       – Submit user feedback on classification
  GET  /api/training       – Get training mode sample emails
All endpoints return JSON. Input is sanitised before processing.
============================================================
"""

# Standard library imports
import json        # For serialisation helpers
import logging
from typing import Any, Dict

# Flask imports
from flask import (
    Blueprint, request, jsonify,
    current_app, send_file
)
from flask_limiter import Limiter
from flask_limiter.util import get_remote_address

# Internal imports
from backend.engine.analysis_pipeline   import AnalysisPipeline
from backend.models.database            import db, Rule, AnalysisResult, Email, TriggeredRule, UserFeedback
from backend.utils.sanitiser            import sanitise_input, validate_rule_input
from backend.utils.pdf_exporter         import generate_pdf_report
from backend.utils.training_data        import TRAINING_EMAILS

logger = logging.getLogger(__name__)   # Module-scoped logger

# --- Create the API Blueprint ---
api_blueprint = Blueprint("api", __name__)

# --- Instantiate the analysis pipeline (shared across requests) ---
pipeline = AnalysisPipeline()


# ══════════════════════════════════════════════════════════
#  HELPER: standard JSON error response
# ══════════════════════════════════════════════════════════
def error_response(message: str, status: int = 400) -> Any:
    """Return a consistent JSON error envelope."""
    return jsonify({"success": False, "error": message}), status


# ══════════════════════════════════════════════════════════
#  POST /api/analyse
# ══════════════════════════════════════════════════════════
@api_blueprint.route("/analyse", methods=["POST"])
def analyse():
    """
    Run the full PhishGuard analysis pipeline on a submitted email.
    Accepts JSON body with fields:
      - sender, subject, body_text, body_html, headers, recipient (individual fields)
      - raw_email (full RFC-2822 string; overrides individual fields)
      - language ("en" or "sw")
    Rate limited to 30/minute per IP to prevent abuse.
    """
    data = request.get_json(silent=True)   # silent=True returns None on bad JSON
    if not data:
        return error_response("Request body must be valid JSON.")

    # --- Sanitise all string inputs to prevent XSS and SQL injection ---
    sender    = sanitise_input(data.get("sender",    ""), max_length=512)
    subject   = sanitise_input(data.get("subject",   ""), max_length=1024)
    body_text = sanitise_input(data.get("body_text", ""), max_length=100_000)
    body_html = sanitise_input(data.get("body_html", ""), max_length=500_000, allow_html=True)
    headers   = sanitise_input(data.get("headers",   ""), max_length=20_000)
    recipient = sanitise_input(data.get("recipient", ""), max_length=512)
    raw_email = sanitise_input(data.get("raw_email", ""), max_length=600_000, allow_html=True)
    language  = data.get("language", "en")

    # --- Validate language code ---
    if language not in current_app.config.get("SUPPORTED_LANGUAGES", ["en", "sw"]):
        language = "en"   # Fallback to English for unknown languages

    # --- Require at least some content to analyse ---
    if not any([raw_email, body_text, body_html, subject, sender]):
        return error_response("Please provide email content to analyse.")

    # --- Enforce maximum email size ---
    max_kb = current_app.config.get("MAX_EMAIL_SIZE_KB", 500)
    total_size = len((raw_email or body_text or "").encode("utf-8"))
    if total_size > max_kb * 1024:
        return error_response(f"Email exceeds maximum size of {max_kb} KB.")

    # --- Run the pipeline (catch-all ensures JSON on any unhandled error) ---
    ip_address = request.remote_addr   # Caller's IP for audit trail
    try:
        result = pipeline.run(
            sender     = sender,
            subject    = subject,
            body_text  = body_text,
            body_html  = body_html,
            headers    = headers,
            recipient  = recipient,
            raw_email  = raw_email,
            language   = language,
            ip_address = ip_address,
        )
    except Exception as exc:
        # Unhandled exception — log the full traceback, return structured JSON
        # so the browser never receives Flask's HTML 500 page
        logger.exception(f"[API] Unhandled pipeline exception: {exc}")
        return jsonify({
            "success":        False,
            "error":          "An unexpected server error occurred. Check logs.",
            "risk_score":     0,
            "classification": "unknown",
            "confidence":     0,
            "explanation":    {},
        }), 500

    # --- Return appropriate HTTP status based on outcome ---
    status_code = 200 if result.get("success") else 500
    return jsonify(result), status_code


# ══════════════════════════════════════════════════════════
#  GET /api/history
# ══════════════════════════════════════════════════════════
@api_blueprint.route("/history", methods=["GET"])
def history():
    """
    Return paginated analysis history for the dashboard history table.
    Query params:
      - page (int, default 1)
      - per_page (int, default 20, max 100)
      - classification ("legitimate"|"suspicious"|"phishing"|"all")
    """
    page           = max(1, request.args.get("page", 1, type=int))
    per_page       = min(100, request.args.get("per_page", 20, type=int))
    classification = request.args.get("classification", "all")

    # --- Build base query joining AnalysisResult with Email ---
    query = (
        db.session.query(AnalysisResult, Email)
        .join(Email, AnalysisResult.email_id == Email.id)
        .order_by(AnalysisResult.analysed_at.desc())   # Newest first
    )

    # --- Apply optional classification filter ---
    if classification in ("legitimate", "suspicious", "phishing"):
        query = query.filter(AnalysisResult.classification == classification)

    # --- Execute paginated query ---
    try:
        pagination = query.paginate(page=page, per_page=per_page, error_out=False)
    except Exception as exc:
        logger.error(f"[API] /history DB error: {exc}")
        return error_response(
            "Database unavailable. Check MySQL connection and run db migrations.",
            503,
        )

    # --- Serialise each row ---
    items = []
    for analysis, email_row in pagination.items:
        items.append({
            "id":             analysis.id,
            "email_id":       email_row.id,
            "sender":         email_row.sender or "Unknown",
            "subject":        email_row.subject or "(No subject)",
            "risk_score":     analysis.risk_score,
            "classification": analysis.classification,
            "confidence":     analysis.confidence,
            "analysed_at":    analysis.analysed_at.isoformat() if analysis.analysed_at else None,
            "processing_ms":  analysis.processing_time,
        })

    return jsonify({
        "success":     True,
        "items":       items,
        "total":       pagination.total,
        "page":        page,
        "per_page":    per_page,
        "pages":       pagination.pages,
    })


# ══════════════════════════════════════════════════════════
#  GET /api/stats
# ══════════════════════════════════════════════════════════
@api_blueprint.route("/stats", methods=["GET"])
def stats():
    """
    Return aggregated statistics for the analytics dashboard.
    Includes: total counts, classification breakdown, top triggered rules,
    average risk score, and recent trend data.
    """
    from sqlalchemy import func   # Import here to avoid top-level circular import

    try:
        # --- Total email counts ---
        total = AnalysisResult.query.count()
    except Exception as exc:
        logger.error(f"[API] /stats DB error: {exc}")
        return error_response(
            "Database unavailable. Check MySQL connection and run db migrations.",
            503,
        )

    if total == 0:
        return jsonify({
            "success":       True,
            "total":         0,
            "legitimate":    0,
            "suspicious":    0,
            "phishing":      0,
            "avg_risk_score":0.0,
            "top_rules":     [],
            "trend":         [],
        })

    # --- Count by classification ---
    clf_counts = (
        db.session.query(AnalysisResult.classification, func.count(AnalysisResult.id))
        .group_by(AnalysisResult.classification)
        .all()
    )
    counts = {"legitimate": 0, "suspicious": 0, "phishing": 0}
    for clf, cnt in clf_counts:
        counts[clf] = cnt

    # --- Average risk score ---
    avg_score = db.session.query(func.avg(AnalysisResult.risk_score)).scalar() or 0.0

    # --- Top 10 most frequently triggered rules ---
    from backend.models.database import Rule as RuleModel
    top_rules_query = (
        db.session.query(RuleModel.rule_id, RuleModel.name, func.count(TriggeredRule.id).label("trigger_count"))
        .join(TriggeredRule, TriggeredRule.rule_id == RuleModel.id)
        .group_by(RuleModel.rule_id, RuleModel.name)
        .order_by(func.count(TriggeredRule.id).desc())
        .limit(10)
        .all()
    )
    top_rules = [
        {"rule_id": r.rule_id, "name": r.name, "count": r.trigger_count}
        for r in top_rules_query
    ]

    # --- Daily trend for the last 14 days ---
    from datetime import datetime, timedelta
    today      = datetime.utcnow().date()
    trend_data = []
    for i in range(13, -1, -1):   # 14 days, oldest first
        day = today - timedelta(days=i)
        day_start = datetime.combine(day, datetime.min.time())
        day_end   = datetime.combine(day, datetime.max.time())

        day_count = (
            AnalysisResult.query
            .filter(AnalysisResult.analysed_at.between(day_start, day_end))
            .count()
        )
        phish_count = (
            AnalysisResult.query
            .filter(
                AnalysisResult.analysed_at.between(day_start, day_end),
                AnalysisResult.classification == "phishing"
            )
            .count()
        )
        trend_data.append({
            "date":    day.isoformat(),
            "total":   day_count,
            "phishing":phish_count,
        })

    return jsonify({
        "success":        True,
        "total":          total,
        "legitimate":     counts.get("legitimate", 0),
        "suspicious":     counts.get("suspicious", 0),
        "phishing":       counts.get("phishing", 0),
        "avg_risk_score": round(float(avg_score), 2),
        "top_rules":      top_rules,
        "trend":          trend_data,
    })


# ══════════════════════════════════════════════════════════
#  GET /api/rules
# ══════════════════════════════════════════════════════════
@api_blueprint.route("/rules", methods=["GET"])
def get_rules():
    """
    Return all rules (enabled and disabled) for the Rule Management UI.
    Query params:
      - category (filter by category)
      - enabled  ("true"|"false"|"all", default "all")
    """
    category_filter = request.args.get("category", "all")
    enabled_filter  = request.args.get("enabled",  "all")

    query = Rule.query.order_by(Rule.category, Rule.rule_id)

    if category_filter != "all":
        query = query.filter(Rule.category == category_filter)

    if enabled_filter == "true":
        query = query.filter(Rule.is_enabled == True)
    elif enabled_filter == "false":
        query = query.filter(Rule.is_enabled == False)

    rules = query.all()

    return jsonify({
        "success": True,
        "rules": [
            {
                "id":          r.id,
                "rule_id":     r.rule_id,
                "name":        r.name,
                "category":    r.category,
                "weight":      r.weight,
                "description": r.description,
                "pattern":     r.pattern,
                "is_enabled":  r.is_enabled,
                "is_custom":   r.is_custom,
                "created_at":  r.created_at.isoformat() if r.created_at else None,
            }
            for r in rules
        ],
        "total": len(rules),
    })


# ══════════════════════════════════════════════════════════
#  POST /api/rules  — Create custom rule
# ══════════════════════════════════════════════════════════
@api_blueprint.route("/rules", methods=["POST"])
def create_rule():
    """
    Create a new custom detection rule via the Rule Management UI.
    Required JSON fields: name, category, weight, pattern
    Optional: description
    """
    data = request.get_json(silent=True)
    if not data:
        return error_response("Request body must be valid JSON.")

    # --- Validate and sanitise rule fields ---
    errors = validate_rule_input(data)
    if errors:
        return error_response(f"Validation failed: {'; '.join(errors)}")

    # --- Generate a unique rule_id for custom rules ---
    custom_count = Rule.query.filter_by(is_custom=True).count()
    rule_id = f"CUSTOM_{custom_count + 1:03d}"   # e.g. "CUSTOM_001"

    # --- Create and persist the new rule ---
    new_rule = Rule(
        rule_id     = rule_id,
        name        = sanitise_input(data["name"], max_length=256),
        category    = data["category"],
        weight      = float(data["weight"]),
        description = sanitise_input(data.get("description", ""), max_length=1000),
        pattern     = sanitise_input(data["pattern"], max_length=1000),
        is_enabled  = True,
        is_custom   = True,
    )
    db.session.add(new_rule)
    db.session.commit()

    logger.info(f"[API] Custom rule created: {rule_id}")
    return jsonify({"success": True, "rule_id": rule_id, "id": new_rule.id}), 201


# ══════════════════════════════════════════════════════════
#  PATCH /api/rules/<id>  — Toggle or update a rule
# ══════════════════════════════════════════════════════════
@api_blueprint.route("/rules/<int:rule_id>", methods=["PATCH"])
def update_rule(rule_id: int):
    """
    Toggle a rule's enabled state, or update weight/description.
    Used by the Rule Management UI toggle switches.
    """
    rule = Rule.query.get_or_404(rule_id)   # 404 if rule doesn't exist
    data = request.get_json(silent=True) or {}

    # --- Apply only provided fields (partial update) ---
    if "is_enabled" in data:
        rule.is_enabled = bool(data["is_enabled"])

    if "weight" in data:
        w = float(data["weight"])
        if 0.1 <= w <= 5.0:   # Enforce reasonable weight range
            rule.weight = w

    if "description" in data:
        rule.description = sanitise_input(data["description"], max_length=1000)

    db.session.commit()   # Persist changes
    return jsonify({"success": True, "rule_id": rule.rule_id, "is_enabled": rule.is_enabled})


# ══════════════════════════════════════════════════════════
#  GET /api/export/<analysis_id>  — Export PDF report
# ══════════════════════════════════════════════════════════
@api_blueprint.route("/export/<int:analysis_id>", methods=["GET"])
def export_pdf(analysis_id: int):
    """
    Generate and return a PDF analysis report for the given analysis ID.
    Uses WeasyPrint to render an HTML template to PDF.
    """
    # --- Load the analysis result with eager-loaded relationships ---
    analysis = AnalysisResult.query.get_or_404(analysis_id)
    email_row = Email.query.get_or_404(analysis.email_id)

    triggered = (
        db.session.query(TriggeredRule, Rule)
        .join(Rule, TriggeredRule.rule_id == Rule.id)
        .filter(TriggeredRule.analysis_result_id == analysis_id)
        .all()
    )

    # --- Build the data dict for the PDF template ---
    report_data = {
        "analysis":        analysis,
        "email":           email_row,
        "triggered_rules": triggered,
        "category_scores": analysis.category_scores_dict(),
    }

    language = request.args.get("lang", email_row.language or "en")

    try:
        pdf_path = generate_pdf_report(report_data, analysis_id, language)
        return send_file(
            pdf_path,
            as_attachment   = True,
            download_name   = f"phishguard_report_{analysis_id}.pdf",
            mimetype        = "application/pdf"
        )
    except Exception as exc:
        logger.error(f"[API] PDF generation failed for analysis {analysis_id}: {exc}")
        return error_response("PDF generation failed. Please ensure WeasyPrint is installed.", 500)


# ══════════════════════════════════════════════════════════
#  POST /api/feedback  — Submit user feedback
# ══════════════════════════════════════════════════════════
@api_blueprint.route("/feedback", methods=["POST"])
def submit_feedback():
    """
    Accept analyst feedback on an analysis result.
    Helps track false positive/negative rates over time.
    Required JSON fields: analysis_result_id, is_correct
    Optional: correct_label, comment
    """
    data = request.get_json(silent=True)
    if not data:
        return error_response("Request body must be valid JSON.")

    analysis_id = data.get("analysis_result_id")
    is_correct  = data.get("is_correct")

    if analysis_id is None or is_correct is None:
        return error_response("Fields 'analysis_result_id' and 'is_correct' are required.")

    # --- Verify the analysis exists ---
    analysis = AnalysisResult.query.get(analysis_id)
    if not analysis:
        return error_response(f"Analysis {analysis_id} not found.", 404)

    # --- Upsert feedback (one per analysis) ---
    feedback = UserFeedback.query.filter_by(analysis_result_id=analysis_id).first()
    if feedback:
        feedback.is_correct    = bool(is_correct)
        feedback.correct_label = data.get("correct_label")
        feedback.comment       = sanitise_input(data.get("comment", ""), max_length=500)
    else:
        feedback = UserFeedback(
            analysis_result_id = analysis_id,
            is_correct         = bool(is_correct),
            correct_label      = data.get("correct_label"),
            comment            = sanitise_input(data.get("comment", ""), max_length=500),
        )
        db.session.add(feedback)

    db.session.commit()
    return jsonify({"success": True, "message": "Feedback recorded."})


# ══════════════════════════════════════════════════════════
#  GET /api/training  — Training mode sample emails
# ══════════════════════════════════════════════════════════
@api_blueprint.route("/training", methods=["GET"])
def get_training_emails():
    """
    Return a curated set of sample emails for the Training Mode.
    Includes both legitimate and phishing examples with expected labels.
    Query params:
      - type ("phishing"|"legitimate"|"suspicious"|"all")
    """
    email_type = request.args.get("type", "all")

    samples = TRAINING_EMAILS   # Loaded from utils/training_data.py

    if email_type in ("phishing", "legitimate", "suspicious"):
        samples = [e for e in samples if e.get("expected_type") == email_type]

    return jsonify({
        "success": True,
        "samples": samples,
        "total":   len(samples),
    })
