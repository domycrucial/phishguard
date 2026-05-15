"""
backend/engine/legitimacy_engine.py
======================================
Legitimacy Engine — subtracts score when genuine legitimacy signals appear.

THE PROBLEM IT SOLVES
---------------------
Pure additive scoring (v1) caused false positives whenever legitimate emails
contained incidental suspicious-looking content. For example, a security
newsletter discussing phishing would fire "credential harvesting keywords"
because the word "password" appears in a warning context.

THE SOLUTION
------------
Real legitimate emails possess structural characteristics that phishing emails
CANNOT replicate without controlling the sending infrastructure:

  1. DKIM pass  → cryptographic proof the domain sent this email
  2. SPF pass   → sending server is authorised by the domain owner
  3. Dual auth  → both DKIM + SPF passing is extremely rare in phishing
  4. Personal greeting → mass campaigns cannot personalise cheaply
  5. Proper Message-ID → well-formed server-generated ID
  6. List-Unsubscribe → legitimate bulk email standard header
  7. No suspicious URLs → all links go to trusted destinations
  8. Known provider + auth → major ESP with valid DKIM

DEDUCTION TABLE (normalised 0-100 scale)
  dkim_pass                    →  -8.0
  spf_pass                     →  -5.0
  dkim_pass AND spf_pass bonus →  -3.0
  personalised (non-generic)   →  -4.0
  proper message-id            →  -3.0
  list-unsubscribe header      →  -3.0
  no suspicious URLs           →  -2.0
  known provider + dkim        →  -2.0
  ---
  Maximum total deduction      → -25.0  (caps to prevent over-reduction)
"""

import logging
from dataclasses import dataclass, field
from typing import List, Dict

from backend.engine.feature_engine import FeatureSet

logger = logging.getLogger(__name__)


# ============================================================
# RESULT OBJECT
# ============================================================

@dataclass
class LegitimacyResult:
    """
    Legitimacy deduction to subtract from the normalised phishing score.

    legitimacy_deduction: Total points to subtract (always ≥ 0).
    deduction_reasons:    Each entry explains one legitimacy signal found.
    """
    legitimacy_deduction: float = 0.0
    deduction_reasons: List[Dict] = field(default_factory=list)


# ============================================================
# LEGITIMACY ENGINE
# ============================================================

class LegitimacyEngine:
    """
    Applies negative scoring when legitimate email signals are present.
    The total deduction is capped at 25.0 to ensure strong evidence
    of phishing still overcomes legitimacy signals.
    """

    _MAX_DEDUCTION: float = 30.0  # raised from 25 to accommodate clean-content deduction

    def evaluate(self, feature_set: FeatureSet) -> LegitimacyResult:
        """Run all legitimacy checks and return a LegitimacyResult."""
        result = LegitimacyResult()
        self._apply(result, feature_set)
        logger.info(
            f"[Legitimacy] Deduction: -{result.legitimacy_deduction:.1f} "
            f"({len(result.deduction_reasons)} signals)"
        )
        return result

    def _apply(self, result: LegitimacyResult, fs: FeatureSet) -> None:
        """Evaluate each legitimacy check and accumulate the deduction."""

        def deduct(amount: float, signal: str, explanation: str) -> None:
            """Helper: accumulate deduction and record the reason."""
            result.legitimacy_deduction = min(
                result.legitimacy_deduction + amount,
                self._MAX_DEDUCTION,
            )
            result.deduction_reasons.append({
                "signal":      signal,
                "deduction":   amount,
                "explanation": explanation,
            })

        # ── DKIM pass: cryptographic proof of authenticity ───────────────────
        # fs.dkim_pass is True when DKIM-Signature verified by receiving MTA
        if fs.dkim_pass:
            deduct(
                8.0,
                "DKIM Authenticated",
                "DKIM-Signature passes cryptographic verification. "
                "The sending domain's private key signed this message, "
                "which phishers cannot forge for a domain they don't control.",
            )

        # ── SPF pass: sending server is authorised by domain owner ───────────
        if fs.spf_pass:
            deduct(
                5.0,
                "SPF Authenticated",
                "Received-SPF: pass — the sending mail server is explicitly "
                "authorised to send on behalf of the sender domain. "
                "This reduces the probability of sender spoofing.",
            )

        # ── Dual authentication bonus: DKIM + SPF together ───────────────────
        # Phishing emails almost never pass both simultaneously
        if fs.dkim_pass and fs.spf_pass:
            deduct(
                3.0,
                "Dual Authentication (DKIM + SPF)",
                "Both DKIM and SPF authentication pass simultaneously. "
                "This combination is exceptionally rare in phishing emails "
                "and strongly suggests a legitimate sending infrastructure.",
            )

        # ── Personalised greeting: mass phishing cannot personalise ──────────
        # Only deduct if:
        #   (a) real personal name found (NOT "Dear Customer" / "Dear User"), AND
        #   (b) NOT a BEC pattern (financial + secrecy) — BEC attacks deliberately
        #       use personalised greetings as social engineering; giving a legitimacy
        #       deduction there would suppress the score on a dangerous attack.
        is_bec_pattern = fs.has_financial_request and fs.has_secrecy_request
        if (
            fs.recipient_personally_addressed
            and not fs.has_generic_greeting
            and not is_bec_pattern
        ):
            deduct(
                4.0,
                "Personalised Greeting",
                "The email addresses the recipient by their real name rather than "
                "a generic title ('Dear Customer'). Mass phishing campaigns cannot "
                "personalise greetings cheaply, making this a legitimacy signal.",
            )

        # ── Proper well-formed Message-ID ────────────────────────────────────
        # not fs.missing_message_id means the header IS present
        # not fs.malformed_message_id means it IS properly formatted
        if not fs.missing_message_id and not fs.malformed_message_id:
            deduct(
                3.0,
                "Proper Message-ID",
                "A well-formed Message-ID (<unique-id@domain>) is present. "
                "Real mail servers always generate properly structured IDs. "
                "Phishing tools frequently omit or malform this header.",
            )

        # ── List-Unsubscribe header: legitimate bulk email standard ──────────
        if fs.has_unsubscribe_header:
            deduct(
                3.0,
                "List-Unsubscribe Header",
                "The List-Unsubscribe header follows RFC 2369 for bulk email. "
                "Phishing emails never include this header because it would "
                "expose their sending infrastructure to abuse complaints.",
            )

        # ── No suspicious URL indicators ─────────────────────────────────────
        # Only deduct if the email has URLs but none are suspicious
        has_clean_urls = (
            fs.url_count > 0
            and not fs.has_ip_url
            and not fs.has_shortener
            and not fs.has_suspicious_tld
            and not fs.has_at_in_url
            and fs.link_text_mismatch_count == 0
        )
        if has_clean_urls:
            deduct(
                2.0,
                "No Suspicious URLs",
                f"The email contains {fs.url_count} URL(s) but none have "
                "suspicious characteristics: no bare IP addresses, no URL "
                "shorteners, no high-abuse TLDs, and no link text mismatches. "
                "This reduces the probability of URL-based phishing.",
            )

        # ── Known provider with valid DKIM ───────────────────────────────────
        # sender_uses_free_email=False + dkim_pass + no typosquatting
        is_verified_provider = (
            not fs.sender_uses_free_email
            and not fs.sender_domain_typosquatting
            and fs.dkim_pass
        )
        if is_verified_provider:
            deduct(
                2.0,
                "Verified Non-Free Provider",
                "Email originates from a non-free-email domain (not Gmail, "
                "Yahoo, etc.) and the domain is not a known lookalike, "
                "with valid DKIM authentication. This combination strongly "
                "suggests a legitimate corporate or service email.",
            )

        # ── Clean email: no strong phishing signals at all ───────────────────
        # This is the most important deduction for field-submitted emails.
        # When a user submits an email via fields (not raw MIME), the
        # authentication headers (DKIM, SPF, Message-ID) are always absent —
        # they ARE present in the real email but not included in the form.
        # Without this deduction, legitimate emails from Gmail or Yahoo would
        # score 25-30% purely from "DKIM absent" + "Missing Message-ID" +
        # "free email provider" — all of which are structural artifacts, not
        # actual phishing evidence.
        #
        # We deduct 8 points when NONE of the characteristic phishing
        # signals are present in the content or URL structure. Only strong
        # phishing indicators disqualify this deduction:
        no_strong_phishing = (
            not fs.has_urgency_language            # no pressure tactics
            and not fs.has_credential_request      # not harvesting passwords/PINs
            and not fs.has_prize_language          # no fake lottery/prize lures
            and not fs.has_financial_request       # no wire transfer demands
            and not fs.has_fear_language           # no threats/arrest warnings
            and not fs.has_secrecy_request         # no BEC confidentiality demands
            and not fs.has_gift_card_request       # no gift card scams
            and not fs.has_crypto_request          # no cryptocurrency demands
            and fs.link_text_mismatch_count == 0   # no visual link deception
            and not fs.has_ip_url                  # no bare IP addresses
            and not fs.has_suspicious_tld          # no .tk/.xyz high-abuse TLDs
            and not fs.sender_domain_typosquatting # no lookalike brand domain
            and not fs.sender_display_name_brand_mismatch  # no display-name spoofing
        )
        if no_strong_phishing:
            deduct(
                12.0,
                "No Phishing Signals Detected",
                "The email contains none of the characteristic phishing indicators: "
                "no urgency pressure, no credential harvesting, no financial demands, "
                "no suspicious URLs, no sender domain deception. "
                "This significantly reduces the phishing probability even when "
                "authentication headers are absent (common in field submissions).",
            )

        # Final cap — enforced inside deduct() but double-checked here
        if result.legitimacy_deduction > self._MAX_DEDUCTION:
            result.legitimacy_deduction = self._MAX_DEDUCTION
