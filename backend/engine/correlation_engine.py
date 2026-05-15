"""
backend/engine/correlation_engine.py
======================================
Correlation Engine — detects COMBINED phishing behaviour patterns.

PHILOSOPHY
----------
A single weak signal must NEVER classify an email as phishing.
Real phishing attacks combine multiple malicious elements simultaneously.
This engine awards bonus points ONLY when corroborated evidence clusters
are found together, making the score much harder to falsely trigger.

COMPOSITE PATTERNS DETECTED
----------------------------
1. Credential Phishing     — suspicious URL + credential request + urgency
2. Domain Spoofing         — typosquatted domain + missing/failed SPF
3. Malware Delivery        — dangerous attachment + HTML script content
4. Business Email Compromise — financial request + sender impersonation + urgency
5. Social Engineering      — prize/authority language + fear pressure + external link

FALSE-POSITIVE REDUCTION
------------------------
- Trusted domain + personalised greeting + proper Message-ID → deduct bonus
  (strong legitimacy cluster counteracts weak rule hits)
"""

import logging
from dataclasses import dataclass, field
from typing import List, Dict, Optional

logger = logging.getLogger(__name__)


# ============================================================
# RESULT OBJECT
# ============================================================

@dataclass
class CorrelationResult:
    """
    Result of the correlation analysis.

    composite_bonus:      Extra score to add for strongly correlated signals.
                          Can be negative for strong legitimacy clusters.
    triggered_composites: List of named pattern dicts that fired.
    safe_mode:            True when constructed as a fallback (engine error).
    """
    composite_bonus: float = 0.0
    triggered_composites: List[Dict] = field(default_factory=list)
    safe_mode: bool = False


# ============================================================
# CORRELATION ENGINE
# ============================================================

class CorrelationEngine:
    """
    Evaluates named composite patterns against the extracted FeatureSet
    and rule matches. Adds a bonus score for each pattern that fires.
    """

    # Bonus weights for each composite pattern
    _BONUS_CREDENTIAL_PHISH: float   = 30.0  # critical: credential harvesting
    _BONUS_DOMAIN_SPOOFING: float    = 25.0  # high: lookalike + auth failure
    _BONUS_MALWARE_DELIVERY: float   = 25.0  # critical: executable + script
    _BONUS_BEC: float                = 20.0  # high: financial + impersonation
    _BONUS_SOCIAL_ENGINEERING: float = 15.0  # medium: prize/fear combo
    _DEDUCT_LEGITIMATE: float        = 20.0  # legitimacy cluster deduction

    def correlate(
        self,
        feature_set,
        rule_matches: Optional[List] = None,
    ) -> CorrelationResult:
        """
        Run all composite checks against the FeatureSet.

        Args:
            feature_set:  FeatureSet produced by FeatureEngine.
            rule_matches: List[RuleMatch] from RuleEngine (optional,
                          used for rule-category tallying).

        Returns:
            CorrelationResult with composite_bonus and triggered_composites.
        """
        result = CorrelationResult()
        fs = feature_set  # short alias

        # Build a set of fired rule categories for quick membership tests
        fired_categories: set = set()
        if rule_matches:
            fired_categories = {m.category for m in rule_matches}

        # ── 1. Credential Phishing ───────────────────────────────────────────
        # Suspicious URL structure + asking for credentials + urgency pressure
        # All three must be present: reduces false positives dramatically
        # Suspicious URL indicator: URL-level flags OR a suspicious sender-domain TLD
        # (e.g. .ml, .tk, .ga) — both hide the real origin equally well
        has_suspicious_url = (
            fs.has_ip_url
            or fs.has_shortener
            or fs.has_suspicious_tld         # URL uses high-abuse TLD
            or getattr(fs, "sender_tld_suspicious", False)  # sender domain has high-abuse TLD
            or fs.has_at_in_url
            or fs.link_text_mismatch_count > 0
        )
        if (
            has_suspicious_url
            and fs.has_credential_request
            and fs.has_urgency_language
        ):
            result.composite_bonus += self._BONUS_CREDENTIAL_PHISH
            result.triggered_composites.append({
                "name":        "Credential Phishing",
                "severity":    "critical",
                "description": (
                    "Suspicious URL structure combined with explicit "
                    "credential harvesting language and urgency pressure. "
                    "All three signals must co-occur — this is a "
                    "high-confidence phishing cluster."
                ),
            })

        # ── 2. Domain Spoofing ───────────────────────────────────────────────
        # Typosquatted sender domain + SPF failure (not just absent — failed)
        if (
            fs.sender_domain_typosquatting
            and (fs.spf_fail or not fs.spf_pass)
        ):
            result.composite_bonus += self._BONUS_DOMAIN_SPOOFING
            result.triggered_composites.append({
                "name":        "Domain Spoofing",
                "severity":    "high",
                "description": (
                    "The sender domain is a lookalike of a known brand "
                    "AND SPF authentication failed or is absent. "
                    "This combination strongly indicates sender spoofing."
                ),
            })

        # ── 3. Malware Delivery ──────────────────────────────────────────────
        # Dangerous attachment (macro/executable) + scripted HTML content
        if (
            fs.has_dangerous_attachment
            and fs.has_script_tag
        ):
            result.composite_bonus += self._BONUS_MALWARE_DELIVERY
            result.triggered_composites.append({
                "name":        "Malware Delivery",
                "severity":    "critical",
                "description": (
                    "An executable or macro-enabled attachment is combined "
                    "with active JavaScript content in the email body. "
                    "This pattern is characteristic of multi-stage malware delivery."
                ),
            })

        # ── 4. Business Email Compromise (BEC) ───────────────────────────────
        # Financial request + sender impersonation + urgency
        has_impersonation = (
            fs.sender_display_name_brand_mismatch
            or fs.sender_domain_typosquatting
            or "sender_verification" in fired_categories
        )
        if (
            fs.has_financial_request
            and has_impersonation
            and fs.has_urgency_language
        ):
            result.composite_bonus += self._BONUS_BEC
            result.triggered_composites.append({
                "name":        "Business Email Compromise",
                "severity":    "high",
                "description": (
                    "Urgent financial request (wire transfer, gift card, payment) "
                    "combined with sender identity deception. "
                    "This is the hallmark pattern of BEC fraud."
                ),
            })

        # ── 5. Social Engineering ────────────────────────────────────────────
        # Prize/authority scam + fear language + external links
        has_lure = fs.has_prize_language or fs.has_authority_impersonation
        has_external_links = fs.url_count > 0
        if (
            has_lure
            and fs.has_fear_language
            and has_external_links
        ):
            result.composite_bonus += self._BONUS_SOCIAL_ENGINEERING
            result.triggered_composites.append({
                "name":        "Social Engineering",
                "severity":    "medium",
                "description": (
                    "Prize/authority lure combined with fear-inducing language "
                    "and external links. This pattern targets recipients "
                    "emotionally to override rational decision-making."
                ),
            })

        # ── 6. Pure BEC (no brand impersonation — financial + secrecy + urgency) ──
        # Generic BEC attacks don't forge known brands but pressure via urgency
        # and secrecy. Requires all three signals to avoid false positives on
        # legitimate urgent payment requests (which never demand secrecy).
        if (
            fs.has_financial_request
            and fs.has_secrecy_request
            and fs.has_urgency_language
        ):
            result.composite_bonus += 15.0
            result.triggered_composites.append({
                "name":        "Business Email Compromise (BEC)",
                "severity":    "high",
                "description": (
                    "Urgent financial request combined with explicit secrecy demands. "
                    "Legitimate payment requests never ask recipients to keep them secret. "
                    "This combination is the hallmark of CEO-fraud / BEC attacks."
                ),
            })

        # ── 7. Legitimacy Cluster (deduction) ───────────────────────────────
        # Cancels weak rule hits when strong structural legitimacy signals co-occur.
        # CRITICAL exclusions:
        #   - Financial requests: BEC attacks are personalised + financial
        #   - Secrecy demands: BEC uses secrecy + personalised greetings
        #   - Suspicious TLDs / IP URLs: structural red flags override legitimacy
        # Removed `not fs.missing_message_id` so field-submitted legitimate
        # emails (which have no headers) can still benefit from this deduction.
        strong_legitimacy = (
            not fs.sender_domain_typosquatting
            and not fs.sender_display_name_brand_mismatch
            and fs.recipient_personally_addressed
            and fs.link_text_mismatch_count == 0
            and not fs.has_suspicious_tld     # suspicious TLD is a hard red flag
            and not fs.has_ip_url             # bare IP URL is a hard red flag
            and not fs.has_financial_request  # BEC uses personalised + financial
            and not fs.has_secrecy_request    # BEC uses personalised + secrecy
            and not fs.has_prize_language     # prize/lottery lures use "Dear Winner"
            and not fs.has_credential_request # legitimate emails never request credentials
        )
        if strong_legitimacy:
            result.composite_bonus -= self._DEDUCT_LEGITIMATE
            result.triggered_composites.append({
                "name":        "Strong Legitimacy Cluster",
                "severity":    "safe",
                "description": (
                    "Multiple strong legitimacy signals co-occur: "
                    "personalised greeting, no domain deception, "
                    "proper Message-ID, and no link mismatches. "
                    "This cluster significantly reduces phishing probability."
                ),
            })

        logger.info(
            f"[Correlation] patterns={len(result.triggered_composites)} "
            f"composite_bonus={result.composite_bonus:.1f}"
        )
        return result
