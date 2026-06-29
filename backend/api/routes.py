"""
============================================================
backend/api/routes.py
REST API v1 Routes for PhishGuard.

All endpoints are mounted under /api/v1/ via the Flask Blueprint.

Endpoints:
  POST  /api/v1/analyse          – Run analysis on submitted email
  GET   /api/v1/history          – Paginated analysis history
  GET   /api/v1/stats            – Aggregated statistics for dashboard
  GET   /api/v1/rules            – List all rules
  POST  /api/v1/rules            – Create a custom rule
  PATCH /api/v1/rules/<id>       – Update/toggle a rule
  GET   /api/v1/export/<id>      – Export analysis as PDF
  POST  /api/v1/feedback         – Submit user feedback on classification
  GET   /api/v1/training         – Get training mode sample emails

Classification system: binary — "legitimate" or "phishing".
All endpoints return JSON. Input is sanitised before processing.
============================================================
"""

# Standard library imports
import json        # For serialisation helpers
import logging
import base64      # For decoding browser-masked email content
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
from backend.models.database            import db, Rule, AnalysisResult, Email, TriggeredRule, UserFeedback, BlockedIndicator, RemediationAction
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


def _decode_field(value: str) -> str:
    """
    Decode a browser-masked field that was base64-encoded on the client.
    The browser uses encodeURIComponent + btoa (handles full Unicode); we reverse
    with base64decode + percent-decode to recover the original UTF-8 string.
    Returns value unchanged if decoding fails (plain-text fallback).
    """
    if not value:
        return value
    try:
        from urllib.parse import unquote
        # Reverse of browser: btoa(encodeURIComponent(text)) → str
        raw_bytes = base64.b64decode(value + "==")   # pad in case truncated
        # Each byte was originally a percent-encoded UTF-8 byte
        percent_str = "".join(
            chr(b) if b < 128 else f"%{b:02X}" for b in raw_bytes
        )
        return unquote(percent_str, encoding="utf-8")
    except Exception:
        return value  # Not encoded — treat as plain text


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

    # --- Detect browser-masked (base64-encoded) submission ---
    # When the UI masking feature is active, the client sets _encrypted=True
    # and base64-encodes all content fields so they appear as ****** in the DOM.
    # We decode them here before sanitisation and analysis.
    encrypted = bool(data.get("_encrypted", False))
    _dec = _decode_field if encrypted else (lambda v: v)  # identity when plain

    # --- Sanitise all string inputs to prevent XSS and SQL injection ---
    sender    = sanitise_input(_dec(data.get("sender",    "")), max_length=512)
    subject   = sanitise_input(_dec(data.get("subject",   "")), max_length=1024)
    body_text = sanitise_input(_dec(data.get("body_text", "")), max_length=100_000)
    body_html = sanitise_input(_dec(data.get("body_html", "")), max_length=500_000, allow_html=True)
    headers   = sanitise_input(_dec(data.get("headers",   "")), max_length=20_000)
    recipient = sanitise_input(_dec(data.get("recipient", "")), max_length=512)
    raw_email = sanitise_input(_dec(data.get("raw_email", "")), max_length=600_000, allow_html=True)
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
      - classification ("legitimate"|"phishing"|"all")
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

    # --- Apply optional classification filter (binary system: legitimate | phishing) ---
    if classification in ("legitimate", "phishing"):
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
            "phishing":      0,
            "avg_risk_score":0.0,
            "top_rules":     [],
            "trend":         [],
        })

    # --- Count by classification (legitimate | suspicious | phishing) ---
    clf_counts = (
        db.session.query(AnalysisResult.classification, func.count(AnalysisResult.id))
        .group_by(AnalysisResult.classification)
        .all()
    )
    counts = {"legitimate": 0, "suspicious": 0, "phishing": 0}
    for clf, cnt in clf_counts:
        clf_str = clf.name if hasattr(clf, 'name') else str(clf)
        if clf_str in counts:
            counts[clf_str] = cnt

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

    # --- Category breakdown of triggered rules ---
    cat_counts_query = (
        db.session.query(RuleModel.category, func.count(TriggeredRule.id).label("count"))
        .join(TriggeredRule, TriggeredRule.rule_id == RuleModel.id)
        .group_by(RuleModel.category)
        .all()
    )
    category_breakdown = {}
    for cat, cnt in cat_counts_query:
        cat_str = cat.name if hasattr(cat, 'name') else str(cat)
        category_breakdown[cat_str] = cnt

    # --- Daily trend for the last 14 days ---
    from datetime import datetime, timedelta, timezone
    today      = datetime.now(timezone.utc).date()
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
        "success":            True,
        "total":              total,
        "legitimate":         counts.get("legitimate", 0),
        "suspicious":         counts.get("suspicious", 0),
        "phishing":           counts.get("phishing", 0),
        "avg_risk_score":     round(float(avg_score), 2),
        "top_rules":          top_rules,
        "category_breakdown": category_breakdown,
        "trend":              trend_data,
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
    rule = db.get_or_404(Rule, rule_id)   # 404 if rule doesn't exist
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
    analysis = db.get_or_404(AnalysisResult, analysis_id)
    email_row = db.get_or_404(Email, analysis.email_id)

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
        return error_response(f"PDF generation failed: {str(exc)}", 500)


# ══════════════════════════════════════════════════════════
#  GET /api/export/csv  — Export all history as CSV
# ══════════════════════════════════════════════════════════
@api_blueprint.route("/export/csv", methods=["GET"])
def export_csv():
    """
    Generate and return a CSV file containing all historical analysis records.
    """
    import csv
    import io
    from flask import Response

    try:
        results = (
            db.session.query(AnalysisResult, Email)
            .join(Email, AnalysisResult.email_id == Email.id)
            .order_by(AnalysisResult.analysed_at.desc())
            .all()
        )

        output = io.StringIO()
        writer = csv.writer(output)
        
        # Write header
        writer.writerow([
            "Analysis ID", "Email ID", "Sender", "Recipient", 
            "Subject", "Risk Score", "Classification", 
            "Confidence", "Analysed At", "Processing Time (s)"
        ])

        for analysis, email_row in results:
            writer.writerow([
                analysis.id,
                email_row.id,
                email_row.sender or "",
                email_row.recipient or "",
                email_row.subject or "",
                analysis.risk_score,
                analysis.classification,
                analysis.confidence,
                analysis.analysed_at.isoformat() if analysis.analysed_at else "",
                analysis.processing_time or 0.0
            ])

        output.seek(0)
        return Response(
            output.getvalue(),
            mimetype="text/csv",
            headers={"Content-Disposition": "attachment; filename=phishguard_history.csv"}
        )
    except Exception as exc:
        logger.error(f"[API] CSV export failed: {exc}")
        return error_response(f"CSV export failed: {str(exc)}", 500)


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
    analysis = db.session.get(AnalysisResult, analysis_id)
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
      - type ("phishing"|"legitimate"|"all")
    """
    email_type = request.args.get("type", "all")

    samples = TRAINING_EMAILS   # Loaded from utils/training_data.py

    if email_type in ("phishing", "legitimate"):
        samples = [e for e in samples if e.get("expected_type") == email_type]

    return jsonify({
        "success": True,
        "samples": samples,
        "total":   len(samples),
    })


# ══════════════════════════════════════════════════════════
#  POST /api/v1/remediate  — Quarantine or Blacklist Email/Sender/URLs
# ══════════════════════════════════════════════════════════
@api_blueprint.route("/remediate", methods=["POST"])
def remediate_email():
    """
    Perform local, self-contained remediation operations on a parsed/analyzed email.
    Payload keys:
      - analysis_id: ID of the AnalysisResult table row
      - action: "quarantine" | "block_sender" | "block_urls"
    """
    data = request.get_json(silent=True) or {}
    analysis_id = data.get("analysis_id")
    action = data.get("action")

    if not analysis_id or not action:
        return error_response("Fields 'analysis_id' and 'action' are required.")

    # Fetch AnalysisResult
    analysis = db.session.get(AnalysisResult, analysis_id)
    if not analysis:
        return error_response(f"Analysis result #{analysis_id} not found.", 404)

    email_id = analysis.email_id
    email_record = db.session.get(Email, email_id)
    if not email_record:
        return error_response(f"Email record #{email_id} not found.", 404)


    success = False
    notes = ""
    try:
        if action == "quarantine":
            email_record.status = "quarantined"
            db.session.commit()
            success = True
            notes = "Email status changed to quarantined locally."

        elif action == "block_sender":
            if not email_record.sender:
                return error_response("Email has no sender information to blacklist.")
            
            sender_email = email_record.sender.strip()
            import re
            email_match = re.search(r'<([^>]+)>', sender_email)
            if email_match:
                sender_email = email_match.group(1).strip()

            existing_ind = BlockedIndicator.query.filter_by(value=sender_email).first()
            if not existing_ind:
                indicator = BlockedIndicator(indicator_type="sender", value=sender_email)
                db.session.add(indicator)
            
            success = True
            notes = f"Sender {sender_email} added to local blacklist."

        elif action == "block_urls":
            import re
            from urllib.parse import urlparse
            body = email_record.body_text or ""
            urls = re.findall(r'https?://[^\s>]+', body)
            
            blocked_count = 0
            for url in set(urls):
                try:
                    domain = urlparse(url).netloc
                    if not domain:
                        continue
                    domain = domain.lower()
                    existing_ind = BlockedIndicator.query.filter_by(value=domain).first()
                    if not existing_ind:
                        indicator = BlockedIndicator(indicator_type="domain", value=domain)
                        db.session.add(indicator)
                        blocked_count += 1
                except Exception:
                    pass
            
            success = True
            notes = f"Blacklisted {blocked_count} URL domains extracted from email."

        else:
            return error_response(f"Unknown remediation action '{action}'.")

        # Log remediation action in remediation_logs
        log = RemediationAction(
            email_id=email_id,
            action_type=action,
            status="success" if success else "failed",
            notes=notes
        )
        db.session.add(log)
        db.session.commit()

        return jsonify({
            "success": True,
            "message": f"Remediation action '{action}' completed successfully.",
            "notes": notes
        })

    except Exception as exc:
        db.session.rollback()
        logger.error(f"[Remediation] Failed to execute {action} on email #{email_id}: {exc}")
        try:
            fail_log = RemediationAction(
                email_id=email_id,
                action_type=action,
                status="failed",
                notes=str(exc)
            )
            db.session.add(fail_log)
            db.session.commit()
        except Exception:
            pass
        return error_response(f"Remediation action failed: {str(exc)}", 500)


# ══════════════════════════════════════════════════════════
#  GET /api/v1/trusted-domains  — List trusted domains
# ══════════════════════════════════════════════════════════
@api_blueprint.route("/trusted-domains", methods=["GET"])
def get_trusted_domains():
    from backend.models.database import TrustedDomain
    try:
        domains = TrustedDomain.query.order_by(TrustedDomain.domain).all()
        return jsonify({
            "success": True,
            "domains": [{"id": d.id, "domain": d.domain, "created_at": d.created_at.isoformat() if d.created_at else None} for d in domains]
        })
    except Exception as exc:
        logger.error(f"[API] Failed to get trusted domains: {exc}")
        return error_response(f"Failed to fetch trusted domains: {str(exc)}", 500)


# ══════════════════════════════════════════════════════════
#  POST /api/v1/trusted-domains  — Add trusted domain
# ══════════════════════════════════════════════════════════
@api_blueprint.route("/trusted-domains", methods=["POST"])
def add_trusted_domain():
    from backend.models.database import TrustedDomain
    data = request.get_json(silent=True) or {}
    domain = sanitise_input(data.get("domain", "")).strip().lower()

    if not domain:
        return error_response("Domain field is required.")

    # Simple domain regex validation
    import re
    if not re.match(r"^[a-z0-9]+([\-\.]{1}[a-z0-9]+)*\.[a-z]{2,10}$", domain):
        return error_response("Invalid domain format.")

    try:
        existing = TrustedDomain.query.filter_by(domain=domain).first()
        if existing:
            return error_response(f"Domain '{domain}' is already trusted.")

        new_domain = TrustedDomain(domain=domain)
        db.session.add(new_domain)
        db.session.commit()
        return jsonify({
            "success": True,
            "message": f"Domain '{domain}' added to trusted list.",
            "domain": {"id": new_domain.id, "domain": new_domain.domain}
        }), 201
    except Exception as exc:
        db.session.rollback()
        logger.error(f"[API] Failed to add trusted domain: {exc}")
        return error_response(f"Failed to add trusted domain: {str(exc)}", 500)


# ══════════════════════════════════════════════════════════
#  DELETE /api/v1/trusted-domains/<id>  — Remove trusted domain
# ══════════════════════════════════════════════════════════
@api_blueprint.route("/trusted-domains/<int:domain_id>", methods=["DELETE"])
def delete_trusted_domain(domain_id: int):
    from backend.models.database import TrustedDomain
    try:
        domain = db.session.get(TrustedDomain, domain_id)
        if not domain:
            return error_response("Trusted domain not found.", 404)

        db.session.delete(domain)
        db.session.commit()
        return jsonify({
            "success": True,
            "message": f"Domain '{domain.domain}' removed from trusted list."
        })
    except Exception as exc:
        db.session.rollback()
        logger.error(f"[API] Failed to delete trusted domain: {exc}")
        return error_response(f"Failed to delete trusted domain: {str(exc)}", 500)


