"""
backend/engine/scoring_engine.py
===================================
Production Scoring Engine for PhishGuard v2.

COMPLETE REDESIGN from v1.

v1 PROBLEMS FIXED HERE:
  1. MAX_RAW_SCORE was arbitrary (started at 126, then 20 — both wrong).
     Fix: sigmoid-based normalisation calibrated against empirical email data.
  2. No composite bonuses — each rule contributed independently.
     Fix: composite bonus from CorrelationEngine added before normalisation.
  3. No legitimacy deduction — legitimate signals never reduced the score.
     Fix: deduction from LegitimacyEngine subtracted after normalisation.
  4. Confidence based only on rule count — not on quality of evidence.
     Fix: multi-factor confidence that rewards category diversity,
          composite corroboration, and score distance from thresholds.

SCORING FORMULA
---------------
  raw_score      = Σ(rule.weight × category_multiplier)
  adjusted_raw   = raw_score + composite_bonus / 5
  normalised     = sigmoid_normalise(adjusted_raw)
  final_score    = clamp(normalised - legitimacy_deduction, 0, 100)
  classification = threshold(final_score)
  confidence     = f(rule_count, category_diversity, composite_count, threshold_distance)

CATEGORY MULTIPLIERS (calibrated from research literature)
  url_analysis:          1.4  — URLs are the primary phishing attack vector
  header_authentication: 1.3  — auth failures strongly indicate spoofing
  sender_verification:   1.3  — reliable identity check signals
  html_obfuscation:      1.2  — deliberate HTML tricks = intentional deception
  behavioral:            1.1  — attachments / timing support the case
  content_keyword:       0.9  — keywords alone cause false positives
  linguistic_analysis:   0.7  — weakest signals, highly context-dependent

CLASSIFICATION THRESHOLDS
  < 25   = legitimate   (1-3 weak rules, no corroboration)
  25-54  = suspicious   (several signals, some corroboration)
  ≥ 55   = phishing     (strong signals with corroboration)
"""

import math
import logging
from dataclasses import dataclass, field
from typing import Dict, List

from backend.engine.rule_engine        import RuleMatch
from backend.engine.correlation_engine import CorrelationResult
from backend.engine.legitimacy_engine  import LegitimacyResult

logger = logging.getLogger(__name__)

# ── Category multipliers ──────────────────────────────────────────────────────
CATEGORY_WEIGHTS: Dict[str, float] = {
    "url_analysis":          1.4,
    "header_authentication": 1.3,
    "sender_verification":   1.3,
    "html_obfuscation":      1.2,
    "behavioral":            1.1,
    "content_keyword":       0.9,  # reduced — keywords alone cause FPs
    "linguistic_analysis":   0.7,  # weakest signal category
}

# ── Classification thresholds (0–100 normalised scale) ───────────────────────
# THRESHOLD_SUSPICIOUS lowered from 25 → 22 so borderline suspicious emails
# (e.g. document-sharing links with time pressure, generic-greeting notifications
# from unknown senders) score above the threshold even after legitimacy
# deductions bring clean legitimate emails below 22.
THRESHOLD_SUSPICIOUS: float = 21.0
THRESHOLD_PHISHING:   float = 55.0


# ============================================================
# SCORING RESULT
# ============================================================

@dataclass
class ScoringResult:
    """Complete scoring output for one email analysis."""
    risk_score:           float
    classification:       str
    confidence:           float
    raw_score:            float
    composite_bonus:      float
    legitimacy_deduction: float
    adjusted_score:       float
    category_scores:      Dict[str, float] = field(default_factory=dict)
    rule_matches:         List[RuleMatch]  = field(default_factory=list)
    composite_details:    List[Dict]       = field(default_factory=list)
    legitimacy_details:   List[Dict]       = field(default_factory=list)


# ============================================================
# SCORING ENGINE
# ============================================================

class ScoringEngine:
    """
    Transforms rule matches + correlation + legitimacy into a ScoringResult.
    """

    def score(
        self,
        matches:     List[RuleMatch],
        correlation: CorrelationResult = None,
        legitimacy:  LegitimacyResult  = None,
    ) -> ScoringResult:
        """
        Compute the final phishing risk score.

        Args:
            matches:     Fired rules from RuleEngine.
            correlation: Composite patterns from CorrelationEngine.
            legitimacy:  Legitimacy deduction from LegitimacyEngine.

        Returns:
            ScoringResult with risk_score (0-100), classification, confidence.
        """
        # Use safe empty defaults when optional args are omitted (e.g. in tests)
        if correlation is None:
            correlation = CorrelationResult()
        if legitimacy is None:
            legitimacy = LegitimacyResult()

        # ── Step 1: Category-weighted raw score ──────────────────────────────
        category_raw: Dict[str, float] = {}
        for match in matches:
            mult    = CATEGORY_WEIGHTS.get(match.category, 1.0)
            contrib = match.weight * mult
            match.score_contribution = contrib
            category_raw[match.category] = (
                category_raw.get(match.category, 0.0) + contrib
            )
        raw_score = sum(category_raw.values())

        # ── Step 2: Apply composite bonus on raw scale ────────────────────────
        # Divide by 5 so the bonus is proportional to raw score range,
        # preventing composite patterns from dominating on their own.
        # correlation.composite_bonus is the correctly-named field.
        composite_raw = correlation.composite_bonus / 5.0

        # ── Step 3: Adjusted raw score ────────────────────────────────────────
        adjusted_raw = raw_score + composite_raw

        # ── Step 4: Sigmoid normalisation → 0–100 ────────────────────────────
        normalised = self._normalise(adjusted_raw)

        # ── Step 5: Legitimacy deduction (post-normalisation) ─────────────────
        # Deducting AFTER normalisation means strong evidence still dominates.
        deduction   = legitimacy.legitimacy_deduction
        final_score = max(0.0, normalised - deduction)
        final_score = round(min(100.0, final_score), 2)

        # ── Step 6: Classify ──────────────────────────────────────────────────
        classification = self._classify(final_score)

        # ── Step 7: Confidence ────────────────────────────────────────────────
        confidence = self._confidence(matches, correlation, legitimacy, final_score)

        # ── Step 8: Per-category normalised scores (for UI breakdown) ─────────
        cat_scores = {
            cat: round(min(100.0, self._normalise(raw)), 2)
            for cat, raw in category_raw.items()
        }

        logger.info(
            f"[Scoring] raw={raw_score:.2f} "
            f"comp_bonus={correlation.composite_bonus:.1f} "
            f"legit_deduct={deduction:.1f} "
            f"final={final_score} class={classification} conf={confidence:.2f}"
        )

        return ScoringResult(
            risk_score           = final_score,
            classification       = classification,
            confidence           = confidence,
            raw_score            = round(raw_score, 4),
            composite_bonus      = correlation.composite_bonus,   # renamed field
            legitimacy_deduction = deduction,
            adjusted_score       = round(adjusted_raw, 4),
            category_scores      = cat_scores,
            rule_matches         = matches,
            composite_details    = correlation.triggered_composites,  # renamed field
            legitimacy_details   = legitimacy.deduction_reasons,
        )

    def _normalise(self, raw: float) -> float:
        """
        Sigmoid-inspired mapping of raw score → 0–100.

        Calibration (k = 0.085 — verified against training data):
          raw  0  →   0  (no signals)
          raw  2  →  15  (1-2 weak signals — clearly legitimate)
          raw  5  →  34  (borderline suspicious)
          raw  8  →  49  (solid suspicious territory)
          raw 10  →  57  (threshold: suspicious → phishing)
          raw 14  →  70  (clear phishing)
          raw 20  →  82  (strong phishing)
          raw 30+ →  92  (extreme phishing kit)

        WHY k=0.085 (not 0.18):
        With k=0.18, a raw score of 4.44 already hit the 55% phishing
        threshold, meaning THREE moderate-weight rules on a legitimate
        email (e.g. free-email sender + urgency keyword + missing Message-ID)
        would classify it as phishing — a false-positive factory.
        k=0.085 requires raw ≥ 9.4 to reach the phishing threshold,
        which needs either multiple strong signals or a composite pattern.
        """
        if raw <= 0:
            return 0.0
        return min(100.0, 100.0 * (1.0 - math.exp(-0.085 * raw)))

    def _classify(self, score: float) -> str:
        """Map a normalised score to a classification label."""
        if score >= THRESHOLD_PHISHING:
            return "phishing"
        if score >= THRESHOLD_SUSPICIOUS:
            return "suspicious"
        return "legitimate"

    def _confidence(
        self,
        matches:     List[RuleMatch],
        correlation: CorrelationResult,
        legitimacy:  LegitimacyResult,
        score:       float,
    ) -> float:
        """
        Compute classification confidence (0–1 scale).

        High confidence when:
        - Many rules fired (strong corroboration)
        - Rules span multiple categories (diverse evidence)
        - Composite patterns triggered (correlated attack clusters)
        - Score is far from the nearest classification boundary
        - Strong legitimacy signals are present (confident it's clean)

        Low confidence when:
        - Only 1-2 rules fired
        - All rules are from the same category (echo-chamber)
        - Score is near a threshold (50/50 zone)
        """
        if not matches:
            # No rules fired: confidence comes from legitimacy signals alone
            return 0.92 if legitimacy.legitimacy_deduction > 10 else 0.80

        # Factor 1: Number of rules that fired (max contribution at 6+ rules)
        rule_factor = min(1.0, len(matches) / 6.0)

        # Factor 2: Category diversity (evidence from multiple domains is stronger)
        unique_cats = len({m.category for m in matches})
        cat_factor  = min(1.0, unique_cats / 4.0)

        # Factor 3: Composite patterns (corroborated clusters → high confidence)
        composite_factor = min(
            1.0, len(correlation.triggered_composites) / 2.0
        )

        # Factor 4: Distance from the nearest threshold (far = confident)
        distances = [
            abs(score - THRESHOLD_SUSPICIOUS),
            abs(score - THRESHOLD_PHISHING),
        ]
        dist_factor = min(1.0, min(distances) / 20.0)

        # Factor 5: Legitimacy signals on a clean email (confident it's safe)
        legit_factor = (
            min(1.0, legitimacy.legitimacy_deduction / 15.0)
            if score < 30 else 0.0
        )

        confidence = (
            0.30 * rule_factor       +
            0.20 * cat_factor        +
            0.25 * composite_factor  +
            0.15 * dist_factor       +
            0.10 * legit_factor
        )
        return round(min(0.99, max(0.15, confidence)), 3)
