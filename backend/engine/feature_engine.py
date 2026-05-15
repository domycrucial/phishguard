"""
backend/engine/feature_engine.py
============================================================
PhishGuard v2 - Feature Extraction Engine
============================================================

PURPOSE
-------
Transforms ParsedEmail objects into structured FeatureSet objects.

WHY THIS LAYER EXISTS
---------------------
Older phishing systems directly evaluated raw emails using rules.

That created major problems:
    - Too many false positives
    - Weak indicators triggered alerts
    - No signal correlation
    - No legitimacy balancing
    - Difficult debugging

This engine creates:
    ParsedEmail → FeatureSet → Rules → Correlation → Scoring

Every extracted feature:
    - Has clear meaning
    - Is explainable
    - Is testable
    - Is deterministic
    - Can be independently improved

============================================================
ARCHITECTURE
============================================================

INPUT:
    ParsedEmail

OUTPUT:
    FeatureSet

FEATURE GROUPS:
----------------
1. URL Features
2. Sender Features
3. Authentication Features
4. Content Features
5. HTML Features
6. Attachment Features
7. Linguistic Features
8. Legitimacy Features

============================================================
"""

import re
import math
import logging
import difflib

from dataclasses import dataclass, field
from typing import Dict, List, Optional

from backend.engine.email_parser import (
    ParsedEmail,
    SUSPICIOUS_TLDS
)

logger = logging.getLogger(__name__)


# ============================================================
# KNOWN BRAND DOMAINS
# ============================================================

BRAND_DOMAINS = [
    "paypal.com",
    "amazon.com",
    "google.com",
    "microsoft.com",
    "apple.com",
    "facebook.com",
    "netflix.com",
    "ebay.com",
    "chase.com",
    "bankofamerica.com",
    "wellsfargo.com",
    "crdbbank.com",
    "nmbbank.co.tz",
    "equitybank.co.tz",
    "tra.go.tz",
    "udsm.ac.tz",
    "kcbgroup.com",
]


# ============================================================
# FREE EMAIL PROVIDERS
# ============================================================

FREE_EMAIL_PROVIDERS = frozenset([
    "gmail.com",
    "yahoo.com",
    "hotmail.com",
    "outlook.com",
    "live.com",
    "aol.com",
    "icloud.com",
    "protonmail.com",
    "yandex.com",
    "mail.com",
])


# ============================================================
# FEATURE SET
# ============================================================

@dataclass
class FeatureSet:
    """
    Structured feature vector extracted from ParsedEmail.

    This is the INPUT to:
        - Rule Engine
        - Correlation Engine
        - Scoring Engine
    """

    # ========================================================
    # URL FEATURES
    # ========================================================

    url_count: int = 0
    unique_domain_count: int = 0

    has_ip_url: bool = False
    has_shortener: bool = False
    has_suspicious_tld: bool = False
    has_at_in_url: bool = False
    has_punycode: bool = False
    has_excessive_subdomains: bool = False
    has_hex_ip: bool = False
    has_data_uri: bool = False
    has_js_uri: bool = False

    max_url_length: int = 0
    link_text_mismatch_count: int = 0

    # ========================================================
    # SENDER FEATURES
    # ========================================================

    sender_uses_free_email: bool = False
    sender_display_name_brand_mismatch: bool = False
    sender_domain_typosquatting: bool = False

    typosquatting_target: Optional[str] = None

    reply_to_differs: bool = False
    sender_local_part_random: bool = False
    sender_tld_suspicious: bool = False

    # ========================================================
    # AUTHENTICATION FEATURES
    # ========================================================

    spf_fail: bool = False
    spf_absent: bool = False
    spf_pass: bool = False

    dkim_absent: bool = False
    dkim_pass: bool = False

    dmarc_fail: bool = False
    dmarc_absent: bool = False

    x_mailer_spam_tool: bool = False

    missing_message_id: bool = False
    malformed_message_id: bool = False
    missing_mime_version: bool = False

    high_priority_set: bool = False
    multiple_reply_to: bool = False

    # ========================================================
    # CONTENT FEATURES
    # ========================================================

    has_urgency_language: bool = False
    has_credential_request: bool = False
    has_prize_language: bool = False
    has_financial_request: bool = False
    has_authority_impersonation: bool = False
    has_generic_greeting: bool = False
    has_fear_language: bool = False
    has_secrecy_request: bool = False
    has_gift_card_request: bool = False
    has_crypto_request: bool = False
    has_invoice_scam: bool = False
    has_credential_pressure: bool = False
    has_remote_work_scam: bool = False

    urgency_word_count: int = 0

    # ========================================================
    # HTML FEATURES
    # ========================================================

    has_script_tag: bool = False
    has_iframe: bool = False
    has_meta_refresh: bool = False
    has_form_to_external: bool = False

    hidden_text_count: int = 0
    html_entity_count: int = 0
    html_nesting_depth: int = 0
    inline_style_density: int = 0

    has_svg_payload: bool = False
    has_canvas: bool = False

    external_image_count: int = 0
    has_base64_image: bool = False
    has_external_css: bool = False

    # ========================================================
    # ATTACHMENT FEATURES
    # ========================================================

    has_dangerous_attachment: bool = False
    has_macro_office_file: bool = False
    has_double_extension: bool = False
    has_archive_attachment: bool = False
    has_iso_attachment: bool = False
    has_lnk_attachment: bool = False
    has_html_attachment: bool = False

    # ========================================================
    # LINGUISTIC FEATURES
    # ========================================================

    has_excessive_caps: bool = False
    has_excessive_exclamation: bool = False
    has_broken_grammar: bool = False
    has_invisible_unicode: bool = False

    body_entropy: float = 0.0
    subject_entropy: float = 0.0

    avg_word_length: float = 0.0
    word_count: int = 0

    # ========================================================
    # LEGITIMACY FEATURES
    # ========================================================

    has_unsubscribe_header: bool = False
    has_list_id: bool = False

    recipient_personally_addressed: bool = False

    send_hour_normal: bool = False

    has_plain_text_alternative: bool = False
    reasonable_url_count: bool = False
    subject_thread_reply: bool = False
    low_urgency_score: bool = False

    # ========================================================
    # COMPOSITE SCORES
    # ========================================================

    composite_scores: Dict[str, float] = field(default_factory=dict)


# ============================================================
# FEATURE ENGINE
# ============================================================

class FeatureEngine:
    """
    Extracts structured phishing features from ParsedEmail.
    """

    # ========================================================
    # REGEX PATTERNS
    # ========================================================

    _URGENCY_RE = re.compile(
        r"\b("
        r"urgent|immediately|"
        r"account.{0,10}(suspended|closed|blocked|locked)|"
        r"verify.{0,10}(now|immediately|account)|"
        r"limited.{0,5}time|"
        r"act.{0,5}now|"
        r"deadline|"
        r"expire[sd]?|"
        r"final.{0,5}notice|"
        r"last.{0,5}warning|"
        r"action.{0,5}required|"
        r"respond.{0,5}immediately"
        r")\b",
        re.IGNORECASE | re.DOTALL
    )

    _CREDENTIAL_RE = re.compile(
        r"\b("
        r"password|passwd|"
        r"\bpin\b|"
        r"social.{0,5}security|"
        r"\bssn\b|"
        r"credit.{0,5}card|"
        r"card.{0,5}number|"
        r"\bcvv\b|"
        r"\botp\b|"
        r"one.{0,5}time.{0,5}(password|code)|"
        r"security.{0,5}code|"
        r"bank.{0,5}(account|detail)|"
        r"routing.{0,5}number"
        r")\b",
        re.IGNORECASE | re.DOTALL
    )

    _PRIZE_RE = re.compile(
        r"\b("
        r"congratulations|"
        r"you.{0,10}(won|win|winner)|"
        r"lottery|"
        r"prize|"
        r"reward|"
        r"inherit(ance)?|"
        r"million.{0,5}(dollar|usd)|"
        r"selected.{0,10}winner|"
        r"jackpot|"
        r"free.{0,5}gift|"
        r"claim.{0,5}now"
        r")\b",
        re.IGNORECASE | re.DOTALL
    )

    _FINANCIAL_RE = re.compile(
        r"\b("
        r"wire.{0,5}transfer|"
        r"send.{0,10}money|"
        r"payment.{0,10}(required|due|overdue)|"
        r"invoice.{0,10}attached|"
        r"bank.{0,5}transfer|"
        r"western.{0,5}union|"
        r"moneygram|"
        r"bitcoin|"
        r"crypto.{0,5}payment|"
        r"gift.{0,5}card"
        r")\b",
        re.IGNORECASE | re.DOTALL
    )

    _AUTHORITY_RE = re.compile(
        r"\b("
        r"irs|"
        r"\bfbi\b|"
        r"federal.{0,5}bureau|"
        r"police|"
        r"court.{0,5}order|"
        r"legal.{0,5}action|"
        r"lawsuit|"
        r"subpoena|"
        r"warrant|"
        r"customs.{0,5}(officer|agency)|"
        r"tax.{0,5}authority|"
        r"\btra\b"
        r")\b",
        re.IGNORECASE | re.DOTALL
    )

    _GENERIC_GREETING_RE = re.compile(
        r"\bDear\s+("
        r"Customer|"
        r"User|"
        r"Account.{0,10}Holder|"
        r"Valued.{0,10}(Customer|Client)|"
        r"\bSir\b|"
        r"\bMadam\b|"
        r"Friend|"
        r"Member"
        r")\b",
        re.IGNORECASE
    )

    _BROKEN_GRAMMAR_RE = re.compile(
        r"kindly.{0,10}do.the.needful|"
        r"revert.{0,10}back.{0,10}asap",
        re.IGNORECASE | re.DOTALL
    )

    _SPAM_MAILER_RE = re.compile(
        r"(PHPMailer|Mass.{0,5}Mailer|Bulk.{0,5}Mail)",
        re.IGNORECASE
    )

    # Fear language: arrest, lawsuit, account breach threats
    _FEAR_RE = re.compile(
        r"\b("
        r"will.be.arrested|face.legal.action|"
        r"breach.of.account|account.breached|"
        r"immediately.terminated|criminal.charges|"
        r"law.enforcement.will|police.will"
        r")\b",
        re.IGNORECASE | re.DOTALL
    )

    # Secrecy / confidentiality demands (BEC social engineering)
    _SECRECY_RE = re.compile(
        r"\b("
        r"keep.{0,10}(confidential|secret|private)|"
        r"do.not.tell|do.not.discuss|"
        r"between.us.only|do.not.forward"
        r")\b",
        re.IGNORECASE | re.DOTALL
    )

    # Gift card payment demand (exclusively a scam indicator)
    _GIFT_CARD_RE = re.compile(
        r"\b("
        r"gift.card|itunes.card|steam.card|"
        r"google.play.card|amazon.gift.card|"
        r"buy.{0,10}gift.card|gift.card.code"
        r")\b",
        re.IGNORECASE | re.DOTALL
    )

    # Cryptocurrency payment request (ransomware / extortion)
    _CRYPTO_RE = re.compile(
        r"\b("
        r"bitcoin.address|send.{0,10}bitcoin|"
        r"ethereum.wallet|usdt.address|"
        r"crypto.wallet.address|pay.{0,10}in.bitcoin"
        r")\b",
        re.IGNORECASE | re.DOTALL
    )

    # Credential verification pressure (unsolicited login resets)
    _CRED_PRESSURE_RE = re.compile(
        r"\b("
        r"re.?verify.{0,15}account|"
        r"confirm.{0,10}your.{0,10}(login|credentials|password)|"
        r"update.{0,15}banking.details|"
        r"confirm.{0,10}bank.{0,10}details"
        r")\b",
        re.IGNORECASE | re.DOTALL
    )

    # Remote work / easy income scam (money mule recruitment)
    _REMOTE_WORK_RE = re.compile(
        r"\b("
        r"work.from.home.{0,20}(earn|income|salary)|"
        r"easy.{0,10}income|"
        r"no.experience.needed.{0,20}earn|"
        r"earn.{0,15}per.week.{0,20}from.home"
        r")\b",
        re.IGNORECASE | re.DOTALL
    )

    # ========================================================
    # MAIN ENTRYPOINT
    # ========================================================

    def extract(self, p: ParsedEmail) -> FeatureSet:
        """
        Extract all phishing-related features.
        """

        fs = FeatureSet()

        self._extract_url_features(p, fs)
        self._extract_sender_features(p, fs)
        self._extract_auth_features(p, fs)
        self._extract_content_features(p, fs)
        self._extract_html_features(p, fs)
        self._extract_attachment_features(p, fs)
        self._extract_linguistic_features(p, fs)
        self._extract_legitimacy_features(p, fs)

        logger.info("Feature extraction complete")

        return fs

    # ========================================================
    # URL FEATURES
    # ========================================================

    def _extract_url_features(
        self,
        p: ParsedEmail,
        fs: FeatureSet
    ) -> None:

        fs.url_count = len(p.urls)
        fs.unique_domain_count = len(p.unique_domains)

        fs.has_ip_url = p.has_ip_url
        fs.has_shortener = p.has_shortener
        fs.has_suspicious_tld = p.has_suspicious_tld

        fs.link_text_mismatch_count = p.link_text_mismatches

        fs.max_url_length = max(
            (len(u) for u in p.urls),
            default=0
        )

        for url in p.urls:

            if "@" in url:
                fs.has_at_in_url = True

            if "xn--" in url.lower():
                fs.has_punycode = True

            if re.match(
                r"https?://0x[a-fA-F0-9]+",
                url,
                re.IGNORECASE
            ):
                fs.has_hex_ip = True

            if url.lower().startswith("data:text/html"):
                fs.has_data_uri = True

            if url.lower().startswith("javascript:"):
                fs.has_js_uri = True

            try:
                from urllib.parse import urlparse

                host = urlparse(url).netloc

                if host.count(".") >= 4:
                    fs.has_excessive_subdomains = True

            except Exception:
                logger.exception("Failed URL parsing")

        fs.reasonable_url_count = (
            1 <= fs.url_count <= 8
        )

    # ========================================================
    # SENDER FEATURES
    # ========================================================

    def _extract_sender_features(
        self,
        p: ParsedEmail,
        fs: FeatureSet
    ) -> None:

        domain = p.sender_domain or ""
        sender_name = (p.sender_name or "").lower()

        fs.sender_uses_free_email = (
            domain in FREE_EMAIL_PROVIDERS
        )

        if p.sender_tld in SUSPICIOUS_TLDS:
            fs.sender_tld_suspicious = True

        known_brands = {
            "paypal": "paypal.com",
            "amazon": "amazon.com",
            "google": "google.com",
            "microsoft": "microsoft.com",
            "apple": "apple.com",
            "netflix": "netflix.com",
            "facebook": "facebook.com",
            "crdb": "crdbbank.com",
            "nmb": "nmbbank.co.tz",
        }

        for brand, official_domain in known_brands.items():

            if (
                brand in sender_name
                and not domain.endswith(official_domain)
            ):
                fs.sender_display_name_brand_mismatch = True
                break

        # Typosquatting detection — skip entirely for trusted domains.
        # A subdomain of a known institution (e.g. cse.udsm.ac.tz) is NOT
        # trying to impersonate udsm.ac.tz; it IS part of that institution.
        if not p.trusted_domain and domain:
            for brand_domain in BRAND_DOMAINS:

                # A subdomain of the brand domain is legitimate, not a fake
                if domain == brand_domain or domain.endswith("." + brand_domain):
                    break  # exact match or subdomain → stop, no flag

                similarity = difflib.SequenceMatcher(
                    None, domain, brand_domain
                ).ratio()

                # Require similarity > 0.80 to reduce false positives on
                # legitimately similar-sounding domains (e.g. udom.ac.tz vs
                # udsm.ac.tz are two different real Tanzanian universities).
                if 0.80 < similarity < 1.0:
                    fs.sender_domain_typosquatting = True
                    fs.typosquatting_target = brand_domain
                    break

        if p.reply_to_domain and p.sender_domain:
            fs.reply_to_differs = (
                p.reply_to_domain != p.sender_domain
            )

        if p.sender_email and "@" in p.sender_email:
            local = p.sender_email.split("@")[0]
            # Only flag as random if the local part is 14+ chars AND contains
            # at least 2 digits (genuinely random strings have digit-letter mix).
            # This avoids flagging descriptive words like "nyumbaowner" or
            # "youthministry" that happen to be long but are clearly meaningful.
            has_digits = sum(1 for c in local if c.isdigit()) >= 2
            if (
                len(local) >= 14
                and re.match(r"^[a-z0-9]+$", local, re.IGNORECASE)
                and has_digits
            ):
                fs.sender_local_part_random = True

    # ========================================================
    # AUTH FEATURES
    # ========================================================

    def _extract_auth_features(
        self,
        p: ParsedEmail,
        fs: FeatureSet
    ) -> None:

        spf = p.spf_result or "absent"

        fs.spf_fail = spf in ("fail", "softfail")
        fs.spf_absent = spf == "absent"
        fs.spf_pass = spf == "pass"

        fs.dkim_absent = not p.dkim_present
        fs.dkim_pass = p.dkim_result == "pass"

        fs.dmarc_fail = p.dmarc_result == "fail"
        # Use `not` to catch both "" (no auth header) and None
        fs.dmarc_absent = not p.dmarc_result

        if p.x_mailer:
            fs.x_mailer_spam_tool = bool(
                self._SPAM_MAILER_RE.search(p.x_mailer)
            )

        fs.missing_message_id = not p.has_message_id

        if p.message_id:
            fs.malformed_message_id = not bool(
                re.match(
                    r"^<[^>]+@[^>]+>$",
                    p.message_id.strip()
                )
            )

        # Only flag missing MIME-Version when HTML body actually exists
        fs.missing_mime_version = (
            bool(p.body_html)
            and not p.has_mime_version
        )

        fs.high_priority_set = bool(
            p.x_priority
            and re.search(
                r"\b(1|High)\b",
                p.x_priority,
                re.IGNORECASE
            )
        )

        hdr_str = str(p.headers)

        fs.multiple_reply_to = (
            hdr_str.lower().count("reply-to") > 1
        )

    # ========================================================
    # CONTENT FEATURES
    # ========================================================

    def _extract_content_features(
        self,
        p: ParsedEmail,
        fs: FeatureSet
    ) -> None:

        text = " ".join(filter(None, [
            p.body_text or "",
            p.body_text_from_html or "",
            p.subject or "",
        ]))

        if not text:
            return

        urgency_matches = self._URGENCY_RE.findall(text)

        fs.has_urgency_language = len(urgency_matches) > 0
        fs.urgency_word_count = len(urgency_matches)

        fs.has_credential_request = bool(
            self._CREDENTIAL_RE.search(text)
        )

        fs.has_prize_language = bool(
            self._PRIZE_RE.search(text)
        )

        fs.has_financial_request = bool(
            self._FINANCIAL_RE.search(text)
        )

        fs.has_authority_impersonation = bool(
            self._AUTHORITY_RE.search(text)
        )

        fs.has_generic_greeting = bool(
            self._GENERIC_GREETING_RE.search(text)
        )

        fs.has_broken_grammar = bool(
            self._BROKEN_GRAMMAR_RE.search(text)
        )

        # Fear language: explicit arrest/legal/breach threats
        fs.has_fear_language = bool(
            self._FEAR_RE.search(text)
        )

        # Secrecy demand: BEC social engineering tactic
        fs.has_secrecy_request = bool(
            self._SECRECY_RE.search(text)
        )

        # Gift card demand: exclusively used in scams
        fs.has_gift_card_request = bool(
            self._GIFT_CARD_RE.search(text)
        )

        # Cryptocurrency payment request: ransomware / extortion
        fs.has_crypto_request = bool(
            self._CRYPTO_RE.search(text)
        )

        # Credential verification pressure (unsolicited reset)
        fs.has_credential_pressure = bool(
            self._CRED_PRESSURE_RE.search(text)
        )

        # Remote work / easy income scam (money mule recruitment)
        fs.has_remote_work_scam = bool(
            self._REMOTE_WORK_RE.search(text)
        )

    # ========================================================
    # HTML FEATURES
    # ========================================================

    def _extract_html_features(
        self,
        p: ParsedEmail,
        fs: FeatureSet
    ) -> None:

        fs.has_script_tag = p.has_script
        fs.has_iframe = p.has_iframe
        fs.has_meta_refresh = p.has_meta_refresh

        fs.hidden_text_count = p.hidden_text_count
        fs.html_nesting_depth = p.html_nesting_depth

        fs.inline_style_density = p.inline_style_count

        fs.external_image_count = len(
            p.external_image_domains
        )

        if p.form_actions:
            fs.has_form_to_external = True

        if p.body_html:

            html = p.body_html

            fs.html_entity_count = len(
                re.findall(r"&#\d{2,4};", html)
            )

            fs.has_svg_payload = bool(
                re.search(r"<svg", html, re.IGNORECASE)
            )

            fs.has_canvas = bool(
                re.search(r"<canvas", html, re.IGNORECASE)
            )

            fs.has_base64_image = bool(
                re.search(
                    r"data:image/[a-z]+;base64",
                    html,
                    re.IGNORECASE
                )
            )

            fs.has_external_css = bool(
                re.search(
                    r"<link[^>]+stylesheet",
                    html,
                    re.IGNORECASE
                )
            )

    # ========================================================
    # ATTACHMENT FEATURES
    # ========================================================

    def _extract_attachment_features(
        self,
        p: ParsedEmail,
        fs: FeatureSet
    ) -> None:

        fs.has_dangerous_attachment = (
            p.has_dangerous_attachment
        )

        for name in p.attachment_names:

            lower = name.lower()

            if re.search(r"\.(docm|xlsm|pptm)$", lower):
                fs.has_macro_office_file = True

            if re.search(
                r"\.(pdf|doc|jpg|png)\.(exe|scr|js|bat|cmd)$",
                lower
            ):
                fs.has_double_extension = True

            if re.search(r"\.(zip|rar|7z)$", lower):
                fs.has_archive_attachment = True

            if re.search(r"\.iso$", lower):
                fs.has_iso_attachment = True

            if re.search(r"\.lnk$", lower):
                fs.has_lnk_attachment = True

            if re.search(r"\.html?$", lower):
                fs.has_html_attachment = True

    # ========================================================
    # LINGUISTIC FEATURES
    # ========================================================

    def _extract_linguistic_features(
        self,
        p: ParsedEmail,
        fs: FeatureSet
    ) -> None:

        text = p.body_text or p.body_text_from_html or ""

        fs.body_entropy = p.body_text_entropy
        fs.subject_entropy = p.subject_entropy

        fs.avg_word_length = p.avg_word_length
        fs.word_count = p.word_count

        if text:

            caps_words = re.findall(
                r"\b[A-Z]{5,}\b",
                text
            )

            fs.has_excessive_caps = (
                len(caps_words) > 2
            )

            fs.has_excessive_exclamation = bool(
                re.search(r"!{3,}", text)
            )

        full_text = (
            (p.body_text or "")
            + (p.body_html or "")
            + (p.subject or "")
        )

        fs.has_invisible_unicode = bool(
            re.search(
                "[\u200B-\u200F\uFEFF]",
                full_text
            )
        )

    # ========================================================
    # LEGITIMACY FEATURES
    # ========================================================

    def _extract_legitimacy_features(
        self,
        p: ParsedEmail,
        fs: FeatureSet
    ) -> None:
        """
        Extract positive legitimacy signals.
        """

        fs.has_unsubscribe_header = (
            p.has_unsubscribe_header
        )

        fs.has_list_id = p.has_list_id

        fs.recipient_personally_addressed = (
            p.recipient_named
        )

        fs.send_hour_normal = (
            p.send_hour_utc is not None
            and 6 <= p.send_hour_utc <= 22
        )

        fs.has_plain_text_alternative = bool(
            p.body_text and p.body_html
        )

        fs.subject_thread_reply = (
            p.subject_has_re_fwd
        )

        fs.low_urgency_score = (
            fs.urgency_word_count == 0
        )