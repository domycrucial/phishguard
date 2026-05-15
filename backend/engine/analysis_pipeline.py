"""
backend/engine/analysis_pipeline.py
=====================================
PhishGuard v2.5 — Central Orchestration Pipeline

PIPELINE FLOW
-------------
Input
 ↓ [1] Parse Email          (EmailParser)
 ↓ [2] Normalize Content    (normalizer)
 ↓ [3] Extract Features     (FeatureEngine)
 ↓ [4] Evaluate Rules       (RuleEngine)
 ↓ [5] Correlate Evidence   (CorrelationEngine)
 ↓ [6] Evaluate Legitimacy  (LegitimacyEngine)
 ↓ [7] Calculate Risk Score (ScoringEngine)
 ↓ [8] Generate Explanation (ExplainabilityEngine)
 ↓ [9] Persist Results      (database)
 ↓ Output JSON

DESIGN PRINCIPLES
-----------------
✓ Weak signals NEVER classify phishing alone
✓ Missing DKIM/SPF are informational only
✓ Legitimate domains reduce risk
✓ Multiple strong indicators required for phishing verdict
✓ Every decision is explainable
✓ Fail safely — each stage has isolated error handling
"""

import json
import uuid
import time
import logging
from typing import Dict, Any, Optional

# ── Internal Engines ──────────────────────────────────────────────────────────
from backend.engine.email_parser        import EmailParser
from backend.engine.feature_engine      import FeatureEngine       # canonical FE
from backend.engine.rule_engine         import RuleEngine
from backend.engine.correlation_engine  import CorrelationEngine
from backend.engine.legitimacy_engine   import LegitimacyEngine
from backend.engine.scoring_engine      import ScoringEngine
from backend.engine.explainability_engine import ExplainabilityEngine

# ── Utilities ─────────────────────────────────────────────────────────────────
from backend.utils.normalizer import normalize_email_content

# ── Database Models ───────────────────────────────────────────────────────────
from backend.models.database import db, Email, AnalysisResult, TriggeredRule

# ── Custom Exceptions ─────────────────────────────────────────────────────────
from backend.exceptions import (
    ParsingError,
    FeatureExtractionError,
    RuleEvaluationError,
    ScoringError,
)

logger = logging.getLogger(__name__)


class AnalysisPipeline:
    """
    Orchestrates the full phishing analysis pipeline.
    One shared instance is created per Flask worker process.
    """

    PIPELINE_VERSION = "2.5.0"

    def __init__(self):
        # Instantiate all engines once — they are stateless between analyses
        self.parser      = EmailParser()
        self.features    = FeatureEngine()      # was FeatureExtractor (wrong class)
        self.rules       = RuleEngine()
        self.correlation = CorrelationEngine()
        self.legitimacy  = LegitimacyEngine()
        self.scorer      = ScoringEngine()
        self.explainer   = ExplainabilityEngine()

    # ==========================================================================
    # PUBLIC ENTRY POINT
    # ==========================================================================

    def run(
        self,
        sender: str = "",
        subject: str = "",
        body_text: str = "",
        body_html: str = "",
        headers: str = "",
        recipient: str = "",
        raw_email: str = "",
        language: str = "en",
        ip_address: Optional[str] = None,
    ) -> Dict[str, Any]:
        """
        Run the full analysis pipeline on a submitted email.

        Accepts either a raw RFC-2822 string (raw_email) or individual
        fields (sender, subject, body_text, body_html, headers, recipient).
        Returns a standardised JSON-serialisable result dict.
        """
        trace_id = str(uuid.uuid4())      # unique ID for debugging/audit
        pipeline_start = time.perf_counter()

        # Per-stage timing (exposed in the response for performance monitoring)
        metrics: Dict[str, float] = {
            "parse_ms":         0.0,
            "normalize_ms":     0.0,
            "feature_ms":       0.0,
            "rules_ms":         0.0,
            "correlation_ms":   0.0,
            "legitimacy_ms":    0.0,
            "scoring_ms":       0.0,
            "explainability_ms": 0.0,
            "persist_ms":       0.0,
        }

        logger.info(f"[{trace_id}] Pipeline v{self.PIPELINE_VERSION} started")

        # ── STAGE 1: Parse ────────────────────────────────────────────────────
        t = time.perf_counter()
        try:
            if raw_email and raw_email.strip():
                # Full MIME email supplied — parse all headers/body from it
                parsed = self.parser.parse_raw(raw_email)
            else:
                # Individual fields supplied (API form submission)
                parsed = self.parser.parse_fields(
                    sender    = sender,
                    subject   = subject,
                    body_text = body_text,
                    body_html = body_html,
                    headers   = headers,
                    recipient = recipient,
                )
        except ParsingError as exc:
            logger.error(f"[{trace_id}] Parsing failed: {exc}")
            return self._error("Email parsing failed.", trace_id)
        metrics["parse_ms"] = self._ms(t)

        # ── STAGE 2: Normalize ────────────────────────────────────────────────
        t = time.perf_counter()
        try:
            # Clean up whitespace/encoding artifacts in body content
            parsed.body_text = normalize_email_content(parsed.body_text)
            parsed.body_html = normalize_email_content(parsed.body_html)
        except Exception as exc:
            # Non-fatal: log and continue with raw content
            logger.warning(f"[{trace_id}] Normalization warning: {exc}")
        metrics["normalize_ms"] = self._ms(t)

        # ── STAGE 3: Feature Extraction ───────────────────────────────────────
        t = time.perf_counter()
        try:
            feature_set = self.features.extract(parsed)
        except FeatureExtractionError as exc:
            logger.error(f"[{trace_id}] Feature extraction failed: {exc}")
            return self._error("Feature extraction failed.", trace_id)
        metrics["feature_ms"] = self._ms(t)

        # ── STAGE 4: Rule Engine ──────────────────────────────────────────────
        t = time.perf_counter()
        try:
            # Pass both parsed email AND feature set; rule engine uses
            # parsed_email directly for explainability evidence snippets.
            matches = self.rules.evaluate(
                parsed_email = parsed,
                features     = feature_set,
            )
        except RuleEvaluationError as exc:
            logger.error(f"[{trace_id}] Rule engine failed: {exc}")
            return self._error("Rule evaluation failed.", trace_id)
        metrics["rules_ms"] = self._ms(t)

        # ── STAGE 5: Correlation Engine ───────────────────────────────────────
        t = time.perf_counter()
        try:
            correlation = self.correlation.correlate(
                feature_set  = feature_set,
                rule_matches = matches,
            )
        except Exception as exc:
            logger.warning(f"[{trace_id}] Correlation failed: {exc}")
            # Safe fallback: no composite bonuses applied
            from backend.engine.correlation_engine import CorrelationResult
            correlation = CorrelationResult(safe_mode=True)
        metrics["correlation_ms"] = self._ms(t)

        # ── STAGE 6: Legitimacy Engine ────────────────────────────────────────
        t = time.perf_counter()
        try:
            legitimacy = self.legitimacy.evaluate(feature_set=feature_set)
        except Exception as exc:
            logger.warning(f"[{trace_id}] Legitimacy engine failed: {exc}")
            from backend.engine.legitimacy_engine import LegitimacyResult
            # Safe fallback: no legitimacy deduction
            legitimacy = LegitimacyResult(
                legitimacy_deduction = 0.0,
                deduction_reasons    = [],
            )
        metrics["legitimacy_ms"] = self._ms(t)

        # ── STAGE 7: Scoring ──────────────────────────────────────────────────
        t = time.perf_counter()
        try:
            scoring = self.scorer.score(
                matches     = matches,
                correlation = correlation,
                legitimacy  = legitimacy,
            )
        except ScoringError as exc:
            logger.error(f"[{trace_id}] Scoring failed: {exc}")
            return self._error("Scoring engine failed.", trace_id)
        metrics["scoring_ms"] = self._ms(t)

        # ── STAGE 8: Explainability ───────────────────────────────────────────
        t = time.perf_counter()
        try:
            explanation = self.explainer.explain(
                scoring_result = scoring,   # correct parameter name
                language       = language,
            )
        except Exception as exc:
            logger.warning(f"[{trace_id}] Explainability failed: {exc}")
            explanation = {}
        metrics["explainability_ms"] = self._ms(t)

        # Total pipeline time (before DB persist, which doesn't affect UI)
        processing_ms = self._ms(pipeline_start)

        # ── STAGE 9: Persist ──────────────────────────────────────────────────
        t = time.perf_counter()
        analysis_id = None
        try:
            analysis_id = self._persist(
                parsed         = parsed,
                scoring        = scoring,
                explanation    = explanation,
                feature_set    = feature_set,
                processing_ms  = processing_ms,
                ip_address     = ip_address,
                language       = language,
                sender_in      = sender,
                recipient_in   = recipient,
                subject_in     = subject,
                body_text_in   = body_text,
                body_html_in   = body_html,
                trace_id       = trace_id,
            )
        except Exception as exc:
            logger.error(f"[{trace_id}] Persistence failed: {exc}")
        metrics["persist_ms"] = self._ms(t)

        # Structured final log entry (machine-parseable)
        logger.info({
            "trace_id":         trace_id,
            "pipeline_version": self.PIPELINE_VERSION,
            "risk_score":       scoring.risk_score,
            "classification":   scoring.classification,
            "confidence":       scoring.confidence,
            "rules_triggered":  len(matches),
            "processing_ms":    processing_ms,
        })

        # ── Build and return the response dict ────────────────────────────────
        return {
            "success":            True,
            "trace_id":           trace_id,
            "analysis_id":        analysis_id,
            "pipeline_version":   self.PIPELINE_VERSION,
            "risk_score":         scoring.risk_score,
            "classification":     scoring.classification,
            "confidence":         scoring.confidence,
            "processing_ms":      processing_ms,
            "performance_metrics": metrics,
            "rules_triggered":    len(matches),
            "triggered_rules": [
                {
                    # m.rule_name is a property alias for m.name
                    "rule_name": m.rule_name,
                    # m.severity is a property derived from m.weight
                    "severity":  m.severity,
                    "score":     m.score_contribution,
                    "evidence":  m.evidence,
                }
                for m in matches
            ],
            # correlation_engine.CorrelationResult now uses triggered_composites
            "composite_patterns":   correlation.triggered_composites,
            "legitimacy_signals":   legitimacy.deduction_reasons,
            "legitimacy_deduction": legitimacy.legitimacy_deduction,
            "composite_bonus":      correlation.composite_bonus,
            "category_scores":      scoring.category_scores,
            "email_summary": {
                "sender":           parsed.sender_email or sender,
                "subject":          parsed.subject or subject,
                "has_html":         bool(parsed.body_html),
                "url_count":        parsed.url_count,   # populated by parser
                "attachment_count": len(parsed.attachment_names),
            },
            "explanation": explanation,
        }

    # ==========================================================================
    # DATABASE PERSISTENCE
    # ==========================================================================

    def _persist(
        self,
        parsed,
        scoring,
        explanation,
        feature_set,
        processing_ms: float,
        ip_address: Optional[str],
        language: str,
        sender_in: str,
        recipient_in: str,
        subject_in: str,
        body_text_in: str,
        body_html_in: str,
        trace_id: str,
    ) -> int:
        """
        Persist the full analysis into the database as a single transaction.
        Creates three rows: Email, AnalysisResult, and TriggeredRule per match.
        """
        try:
            # ── Email row ─────────────────────────────────────────────────────
            email_row = Email(
                sender     = (parsed.sender_email or sender_in or "")[:512],
                recipient  = (recipient_in or "")[:512],
                subject    = (parsed.subject or subject_in or "")[:1024],
                body_text  = body_text_in or parsed.body_text,
                body_html  = body_html_in or parsed.body_html,
                raw_headers = str(parsed.headers)[:65_535],
                ip_address = ip_address,
                language   = language,
            )
            db.session.add(email_row)
            db.session.flush()   # obtain email_row.id without committing

            # ── Serialise feature set ─────────────────────────────────────────
            try:
                feature_json = json.dumps(
                    feature_set.__dict__, default=str
                )
            except Exception:
                feature_json = "{}"

            # ── AnalysisResult row ────────────────────────────────────────────
            result_row = AnalysisResult(
                email_id            = email_row.id,
                risk_score          = scoring.risk_score,
                classification      = scoring.classification,
                confidence          = scoring.confidence,
                features_json       = feature_json,
                category_scores     = json.dumps(scoring.category_scores),
                legitimacy_score    = scoring.legitimacy_deduction,
                composite_bonus     = scoring.composite_bonus,
                explanation         = explanation.get("narrative", ""),
                processing_time     = processing_ms,
                trace_id            = trace_id,
                pipeline_version    = self.PIPELINE_VERSION,
            )
            db.session.add(result_row)
            db.session.flush()   # obtain result_row.id

            # ── TriggeredRule audit rows ──────────────────────────────────────
            for match in scoring.rule_matches:
                triggered = TriggeredRule(
                    analysis_result_id = result_row.id,
                    rule_id            = match.rule_db_id,
                    evidence           = (match.evidence or "")[:500],
                    score_contribution = match.score_contribution,
                )
                db.session.add(triggered)

            db.session.commit()
            return result_row.id

        except Exception:
            db.session.rollback()
            raise

    # ==========================================================================
    # HELPERS
    # ==========================================================================

    @staticmethod
    def _ms(start: float) -> float:
        """Elapsed milliseconds since start (perf_counter timestamp)."""
        return round((time.perf_counter() - start) * 1_000, 2)

    @staticmethod
    def _error(message: str, trace_id: str) -> Dict[str, Any]:
        """Standardised pipeline error response."""
        return {
            "success":        False,
            "trace_id":       trace_id,
            "risk_score":     0,
            "classification": "unknown",
            "confidence":     0,
            "error":          message,
            "explanation":    {},
        }
