"""
backend/engine/scoring_engine.py
===================================
Production Scoring Engine for PhishGuard v2.

BINARY CLASSIFICATION MODEL
----------------------------
Two-class verdict only: LEGITIMATE or PHISHING.
All signals that previously fell in the "suspicious" band now push to phishing.

SCORING FORMULA
---------------
  raw_score      = Σ(rule.weight × category_multiplier)
  adjusted_raw   = raw_score + composite_bonus / 5
  normalised     = sigmoid_normalise(adjusted_raw)   [k = 0.085]
  final_score    = clamp(normalised - legitimacy_deduction, 0, 100)
  classification = "phishing" if final_score ≥ 35 else "legitimate"

SIGMOID CALIBRATION (k = 0.085 — original calibration)
  raw  0  →   0   (clean email)
  raw  2  →  15   (1-2 very weak signals — legitimate)
  raw  4  →  29   (several weak signals — legitimate)
  raw  5  →  34   (borderline: legitimacy signals push it under threshold)
  raw  5.2 →  35  (phishing threshold — equivalent to old "suspicious" lower bound)
  raw  7  →  45   (clear phishing)
  raw  10 →  57   (strong phishing)
  raw  14 →  70   (very strong phishing kit)
  raw  20 →  82   (extreme multi-vector attack)

WHY THRESHOLD = 35 (not 47 or 55):
  Old system: suspicious ≥ 21, phishing ≥ 55.
  Binary requirement: anything that was "suspicious" (21–54) must now be
  classified as phishing. A threshold of 35 sits safely above the legitimate
  zone (≤ 20 with legitimacy deductions) while capturing the full old
  suspicious band as phishing.
  The legitimacy engine's -30 max deduction ensures that authenticated,
  clean emails with incidental keyword matches remain below 35.

CATEGORY MULTIPLIERS
  url_analysis:          1.4  — URLs are the primary phishing vector
  header_authentication: 1.3  — auth failures strongly indicate spoofing
  sender_verification:   1.3  — reliable identity check signals
  html_obfuscation:      1.2  — deliberate HTML tricks = intentional deception
  behavioral:            1.1  — attachments / timing support the case
  content_keyword:       0.9  — keywords alone cause false positives; need corroboration
  linguistic_analysis:   0.7  — weakest signals, highly context-dependent
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
    "content_keyword":       0.9,
    "linguistic_analysis":   0.7,
}

# ── Single binary threshold ───────────────────────────────────────────────────
# Score ≥ 35 → phishing.  Score < 35 → legitimate.
# Corresponds to the old "suspicious" lower boundary on the normalised scale,
# ensuring all previously-suspicious signals now route to phishing.
THRESHOLD_PHISHING: float = 35.0

# ── Sigmoid constant (original k=0.085) ──────────────────────────────────────
_SIGMOID_K: float = 0.085


# ============================================================
# SCORING RESULT
# ============================================================

@dataclass
class ScoringResult:
    """Complete scoring output for one email analysis."""
    risk_score:           float
    classification:       str           # "legitimate" | "phishing"
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
    Binary output: legitimate or phishing.
    """

    def score(
        self,
        matches:     List[RuleMatch],
        correlation: CorrelationResult = None,
        legitimacy:  LegitimacyResult  = None,
    ) -> ScoringResult:
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

        # ── Step 2: Composite bonus on raw scale ─────────────────────────────
        composite_raw = correlation.composite_bonus / 5.0

        # ── Step 3: Adjusted raw score ────────────────────────────────────────
        adjusted_raw = raw_score + composite_raw

        # ── Step 4: Sigmoid normalisation → 0–100 ────────────────────────────
        normalised = self._normalise(adjusted_raw)

        # ── Step 5: Legitimacy deduction (post-normalisation) ─────────────────
        deduction   = legitimacy.legitimacy_deduction
        final_score = max(0.0, normalised - deduction)
        final_score = round(min(100.0, final_score), 2)

        # ── Step 6: Binary classify ───────────────────────────────────────────
        classification = "phishing" if final_score >= THRESHOLD_PHISHING else "legitimate"

        # ── Step 7: Confidence ────────────────────────────────────────────────
        confidence = self._confidence(matches, correlation, legitimacy, final_score)

        # ── Step 8: Per-category normalised scores ────────────────────────────
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
            composite_bonus      = correlation.composite_bonus,
            legitimacy_deduction = deduction,
            adjusted_score       = round(adjusted_raw, 4),
            category_scores      = cat_scores,
            rule_matches         = matches,
            composite_details    = correlation.triggered_composites,
            legitimacy_details   = legitimacy.deduction_reasons,
        )

    def _normalise(self, raw: float) -> float:
        """
        Sigmoid mapping raw score → 0–100.
        k=0.085: raw 5.2 → 35 (phishing threshold), raw 10 → 57 (strong phishing).
        """
        if raw <= 0:
            return 0.0
        return min(100.0, 100.0 * (1.0 - math.exp(-_SIGMOID_K * raw)))

    def _confidence(
        self,
        matches:     List[RuleMatch],
        correlation: CorrelationResult,
        legitimacy:  LegitimacyResult,
        score:       float,
    ) -> float:
        """Confidence (0–1). High when: many diverse rules fired + score far from threshold."""
        if not matches:
            return 0.93 if legitimacy.legitimacy_deduction > 10 else 0.80

        rule_factor      = min(1.0, len(matches) / 6.0)
        unique_cats      = len({m.category for m in matches})
        cat_factor       = min(1.0, unique_cats / 4.0)
        composite_factor = min(1.0, len(correlation.triggered_composites) / 2.0)
        dist_factor      = min(1.0, abs(score - THRESHOLD_PHISHING) / 25.0)
        legit_factor     = (
            min(1.0, legitimacy.legitimacy_deduction / 15.0)
            if score < THRESHOLD_PHISHING else 0.0
        )

        confidence = (
            0.28 * rule_factor       +
            0.18 * cat_factor        +
            0.28 * composite_factor  +
            0.16 * dist_factor       +
            0.10 * legit_factor
        )
        return round(min(0.99, max(0.15, confidence)), 3)
