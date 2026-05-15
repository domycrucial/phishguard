"""
backend/models/database.py
==========================
SQLAlchemy ORM models for PhishGuard v2.

Tables:
  emails            – raw email submissions
  analysis_results  – scored results with full feature JSON
  rules             – configurable detection rules
  triggered_rules   – which rules fired per analysis (audit trail)
  user_feedback     – analyst correction feedback
"""
import datetime
import json
from flask_sqlalchemy import SQLAlchemy
from sqlalchemy import Column, Integer, String, Float, Boolean, DateTime, Text, ForeignKey, Enum

db = SQLAlchemy()


class Email(db.Model):
    __tablename__ = "emails"
    id           = Column(Integer, primary_key=True, autoincrement=True)
    sender       = Column(String(512),  nullable=True)
    recipient    = Column(String(512),  nullable=True)
    subject      = Column(String(1024), nullable=True)
    body_text    = Column(Text,         nullable=True)
    body_html    = Column(Text,         nullable=True)
    raw_headers  = Column(Text,         nullable=True)
    submitted_at = Column(DateTime,     default=datetime.datetime.utcnow)
    ip_address   = Column(String(45),   nullable=True)
    language     = Column(String(10),   default="en")
    analysis     = db.relationship("AnalysisResult", back_populates="email", uselist=False)


class AnalysisResult(db.Model):
    __tablename__ = "analysis_results"
    id               = Column(Integer, primary_key=True, autoincrement=True)
    email_id         = Column(Integer, ForeignKey("emails.id"), nullable=False, index=True)
    risk_score       = Column(Float,   nullable=False)
    classification   = Column(
        Enum("legitimate", "suspicious", "phishing", name="classification_enum"),
        nullable=False
    )
    confidence       = Column(Float,   nullable=False, default=0.0)
    # Full feature snapshot (JSON) — enables audit and retraining
    features_json    = Column(Text,    nullable=True)
    # Per-category breakdown (JSON)
    category_scores  = Column(Text,    nullable=True)
    # Legitimacy deduction amount
    legitimacy_score = Column(Float,   nullable=False, default=0.0)
    # Composite rule bonus applied
    composite_bonus  = Column(Float,   nullable=False, default=0.0)
    explanation      = Column(Text,    nullable=True)
    processing_time  = Column(Float,   nullable=True)
    # trace_id links every DB row back to a specific pipeline run's log entry
    trace_id         = Column(String(64),  nullable=True, index=True)
    # pipeline_version lets us correlate results with algorithm changes
    pipeline_version = Column(String(20),  nullable=True)
    analysed_at      = Column(DateTime, default=datetime.datetime.utcnow)
    email            = db.relationship("Email",          back_populates="analysis")
    triggered_rules  = db.relationship("TriggeredRule",  back_populates="analysis_result",
                                       cascade="all, delete-orphan")
    feedback         = db.relationship("UserFeedback",   back_populates="analysis_result",
                                       uselist=False)

    def category_scores_dict(self):
        try:
            return json.loads(self.category_scores) if self.category_scores else {}
        except Exception:
            return {}

    def features_dict(self):
        try:
            return json.loads(self.features_json) if self.features_json else {}
        except Exception:
            return {}


class Rule(db.Model):
    __tablename__ = "rules"
    id          = Column(Integer, primary_key=True, autoincrement=True)
    rule_id     = Column(String(64),  unique=True, nullable=False, index=True)
    name        = Column(String(256), nullable=False)
    category    = Column(
        Enum("url_analysis", "content_keyword", "sender_verification",
             "header_authentication", "html_obfuscation", "behavioral",
             "linguistic_analysis", name="rule_category_enum"),
        nullable=False
    )
    weight      = Column(Float,   nullable=False, default=1.0)
    description = Column(Text,    nullable=True)
    pattern     = Column(Text,    nullable=True)
    is_enabled  = Column(Boolean, default=True)
    is_custom   = Column(Boolean, default=False)
    created_at  = Column(DateTime, default=datetime.datetime.utcnow)
    triggers    = db.relationship("TriggeredRule", back_populates="rule")


class TriggeredRule(db.Model):
    __tablename__      = "triggered_rules"
    id                 = Column(Integer, primary_key=True, autoincrement=True)
    analysis_result_id = Column(Integer, ForeignKey("analysis_results.id"),
                                nullable=False, index=True)
    rule_id            = Column(Integer, ForeignKey("rules.id"),
                                nullable=False, index=True)
    evidence           = Column(String(500), nullable=True)
    score_contribution = Column(Float, nullable=False, default=0.0)
    analysis_result    = db.relationship("AnalysisResult", back_populates="triggered_rules")
    rule               = db.relationship("Rule",           back_populates="triggers")


class UserFeedback(db.Model):
    __tablename__      = "user_feedback"
    id                 = Column(Integer, primary_key=True, autoincrement=True)
    analysis_result_id = Column(Integer, ForeignKey("analysis_results.id"),
                                nullable=False, unique=True)
    is_correct         = Column(Boolean, nullable=False)
    correct_label      = Column(
        Enum("legitimate", "suspicious", "phishing", name="feedback_label_enum"),
        nullable=True
    )
    comment            = Column(Text, nullable=True)
    submitted_at       = Column(DateTime, default=datetime.datetime.utcnow)
    analysis_result    = db.relationship("AnalysisResult", back_populates="feedback")


def init_db():
    """
    Initialise the database: bind app, create tables, run migrations, sync rules.
    Must be called inside an active Flask app context.
    """
    from flask import current_app
    # Bind the app to the db instance (factory pattern)
    db.init_app(current_app._get_current_object())
    # Create any tables that don't exist yet (no-op for existing tables)
    db.create_all()
    # Safely add columns added after the initial deployment
    _run_column_migrations()
    # Sync built-in rules from ALL_RULES — handles both fresh DB (seed)
    # and existing DB (update stale weights/patterns, disable removed rules)
    try:
        _sync_builtin_rules()
    except Exception as exc:
        import logging
        logging.getLogger(__name__).error(f"[DB] Rule sync failed: {exc}")


def _run_column_migrations():
    """
    Add columns that were introduced after the initial table creation.
    Uses SQLAlchemy's schema inspector so this is safe to run on every startup:
    it is a no-op when the columns already exist.

    Supports MySQL and SQLite (test mode).
    """
    import logging
    from sqlalchemy import inspect, text

    log = logging.getLogger(__name__)

    try:
        inspector = inspect(db.engine)
        # Get existing column names in analysis_results
        existing = {
            col["name"]
            for col in inspector.get_columns("analysis_results")
        }
    except Exception as exc:
        # Table doesn't exist yet; create_all() will handle it
        log.debug(f"[DB] Migration skipped (table absent): {exc}")
        return

    # All columns that may be absent from pre-existing tables.
    # Each entry: (column_name, DDL_fragment_for_ALTER_TABLE)
    # The check + ALTER approach works on both MySQL and SQLite.
    REQUIRED_COLUMNS = [
        # Added in v2 initial expansion — some deployments may be missing these
        ("features_json",    "ADD COLUMN features_json TEXT"),
        ("legitimacy_score", "ADD COLUMN legitimacy_score FLOAT NOT NULL DEFAULT 0.0"),
        ("composite_bonus",  "ADD COLUMN composite_bonus FLOAT NOT NULL DEFAULT 0.0"),
        # Added in v2.5 — trace ID and pipeline version for audit trail
        ("trace_id",         "ADD COLUMN trace_id VARCHAR(64)"),
        ("pipeline_version", "ADD COLUMN pipeline_version VARCHAR(20)"),
    ]

    pending = [
        f"ALTER TABLE analysis_results {ddl}"
        for col, ddl in REQUIRED_COLUMNS
        if col not in existing
    ]

    for ddl in pending:
        try:
            db.session.execute(text(ddl))
            db.session.commit()
            log.info(f"[DB] Migration applied: {ddl}")
        except Exception as exc:
            db.session.rollback()
            # Duplicate column error is harmless (race condition on first start)
            log.warning(f"[DB] Migration warning (likely already applied): {exc}")


def _sync_builtin_rules():
    """
    Synchronise the rules table with the current ALL_RULES definition.

    This function runs on every startup and is safe to call repeatedly.
    It performs a proper UPSERT:

    1. For each rule in ALL_RULES:
       - If the rule_id already exists in DB → update name, weight, pattern,
         description, and is_enabled to match the current definition.
       - If the rule_id does NOT exist → insert it as a new row.

    2. For every NON-CUSTOM rule in DB that is NOT in ALL_RULES:
       - Set is_enabled = False (disable stale rules; don't delete, for audit).
       - This handles rules that were removed or commented out in code
         (e.g. HDR_002 "DKIM absent" which caused massive false positives).

    Custom rules (is_custom=True) are NEVER modified.
    """
    import logging
    from backend.engine.rules_definitions import ALL_RULES

    log = logging.getLogger(__name__)
    current_ids = {r["rule_id"] for r in ALL_RULES}
    updated = inserted = disabled = 0

    for rule_data in ALL_RULES:
        existing = Rule.query.filter_by(rule_id=rule_data["rule_id"]).first()
        if existing:
            # Update every mutable field so DB always reflects current code
            existing.name        = rule_data["name"]
            existing.category    = rule_data["category"]
            existing.weight      = rule_data["weight"]
            existing.pattern     = rule_data.get("pattern", "")
            existing.description = rule_data.get("description", "")
            existing.is_enabled  = rule_data.get("is_enabled", True)
            updated += 1
        else:
            db.session.add(Rule(**rule_data))
            inserted += 1

    # Disable built-in rules that are no longer in ALL_RULES
    stale = Rule.query.filter(
        Rule.rule_id.notin_(current_ids),
        Rule.is_custom == False,  # noqa: E712 — SQLAlchemy uses == not is
        Rule.is_enabled == True,
    ).all()
    for rule in stale:
        rule.is_enabled = False
        disabled += 1

    db.session.commit()
    log.info(
        f"[DB] Rule sync complete: "
        f"{updated} updated, {inserted} inserted, {disabled} disabled."
    )
    if inserted:
        print(f"[PhishGuard] {inserted} new rule(s) added.")
    if disabled:
        print(f"[PhishGuard] {disabled} stale rule(s) disabled (no longer in ALL_RULES).")


def _seed_rules():
    """Legacy: kept for compatibility, replaced by _sync_builtin_rules."""
    _sync_builtin_rules()
