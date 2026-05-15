# backend/engine/feature_extractor.py

"""
============================================================
PhishGuard v2 - Simplified Feature Extraction Engine
============================================================
PURPOSE:
    Converts a ParsedEmail into a structured FeatureSet.

WHY THIS VERSION:
    - Cleaner and easier to maintain
    - Faster feature extraction
    - Better false-positive prevention
    - More explainable outputs
    - Ready for RuleEngine + CorrelationEngine

DESIGN:
    ParsedEmail ---> FeatureExtractor ---> FeatureSet

NOTES:
    - No scoring is done here
    - No phishing decision is made here
    - Only extracts meaningful features
============================================================
"""

from dataclasses import dataclass, field
from typing import Optional, Dict, List
from urllib.parse import urlparse

import difflib
import logging
import math
import re

logger = logging.getLogger(__name__)


# ============================================================
# KNOWN CONSTANTS
# ============================================================

FREE_EMAIL_PROVIDERS = {
    "gmail.com",
    "yahoo.com",
    "hotmail.com",
    "outlook.com",
    "live.com",
    "icloud.com",
    "aol.com",
    "protonmail.com",
}

HIGH_RISK_TLDS = {
    ".xyz", ".top", ".click", ".loan", ".win",
    ".gq", ".cf", ".ml", ".ga", ".tk"
}

URL_SHORTENERS = {
    "bit.ly",
    "tinyurl.com",
    "goo.gl",
    "ow.ly",
    "t.co",
    "cutt.ly",
    "rb.gy",
}

KNOWN_BRANDS = {
    "paypal": "paypal.com",
    "amazon": "amazon.com",
    "google": "google.com",
    "microsoft": "microsoft.com",
    "apple": "apple.com",
    "facebook": "facebook.com",
    "netflix": "netflix.com",
    "crdb": "crdbbank.com",
    "nmb": "nmbbank.co.tz",
    "tra": "tra.go.tz",
}

SUSPICIOUS_MAILERS = re.compile(
    r"(phpmailer|bulk.?mail|mass.?mailer|sendblaster|dreammail)",
    re.IGNORECASE,
)


# ============================================================
# FEATURE STRUCTURE
# ============================================================

@dataclass
class FeatureSet:
    """
    Structured feature vector.
    Every feature is explainable.
    """

    # --------------------------------------------------------
    # URL FEATURES
    # --------------------------------------------------------
    url_count: int = 0
    unique_domain_count: int = 0
    has_ip_url: bool = False
    has_shortener: bool = False
    has_high_risk_tld: bool = False
    has_at_symbol_url: bool = False
    has_punycode: bool = False
    has_data_uri: bool = False
    has_javascript_uri: bool = False
    has_long_url: bool = False
    excessive_subdomains: bool = False
    link_mismatch_count: int = 0

    # --------------------------------------------------------
    # SENDER FEATURES
    # --------------------------------------------------------
    sender_domain: Optional[str] = None
    free_email_provider: bool = False
    reply_to_mismatch: bool = False
    sender_name_domain_mismatch: bool = False
    typosquatting_detected: bool = False
    typosquatting_target: Optional[str] = None
    random_local_part: bool = False

    # --------------------------------------------------------
    # AUTHENTICATION FEATURES
    # --------------------------------------------------------
    spf_pass: bool = False
    spf_fail: bool = False
    dkim_pass: bool = False
    dkim_missing: bool = False
    dmarc_fail: bool = False
    suspicious_mailer: bool = False
    missing_message_id: bool = False
    malformed_message_id: bool = False

    # --------------------------------------------------------
    # CONTENT FEATURES
    # --------------------------------------------------------
    urgency_detected: bool = False
    credential_request: bool = False
    financial_request: bool = False
    authority_impersonation: bool = False
    prize_scam_language: bool = False
    generic_greeting: bool = False
    fear_language: bool = False
    secrecy_language: bool = False
    crypto_language: bool = False
    urgency_count: int = 0

    # --------------------------------------------------------
    # HTML FEATURES
    # --------------------------------------------------------
    has_html: bool = False
    has_script: bool = False
    has_iframe: bool = False
    has_meta_refresh: bool = False
    hidden_text: bool = False
    html_entity_obfuscation: bool = False
    external_form_action: bool = False
    external_image_count: int = 0

    # --------------------------------------------------------
    # ATTACHMENT FEATURES
    # --------------------------------------------------------
    attachment_count: int = 0
    dangerous_attachment: bool = False
    macro_attachment: bool = False
    double_extension_attachment: bool = False
    archive_attachment: bool = False
    html_attachment: bool = False

    # --------------------------------------------------------
    # LINGUISTIC FEATURES
    # --------------------------------------------------------
    body_entropy: float = 0.0
    subject_entropy: float = 0.0
    excessive_caps: bool = False
    excessive_exclamation: bool = False
    invisible_unicode: bool = False
    word_count: int = 0

    # --------------------------------------------------------
    # LEGITIMACY FEATURES
    # --------------------------------------------------------
    unsubscribe_header: bool = False
    list_id_header: bool = False
    personally_addressed: bool = False
    known_provider: bool = False
    normal_send_time: bool = False
    has_plain_text_version: bool = False

    # --------------------------------------------------------
    # EXTRA
    # --------------------------------------------------------
    extracted_features: Dict[str, bool] = field(default_factory=dict)


# ============================================================
# FEATURE EXTRACTOR ENGINE
# ============================================================

class FeatureExtractor:
    """
    Main feature extraction engine.
    """

    # --------------------------------------------------------
    # REGEX PATTERNS
    # --------------------------------------------------------

    URGENCY_RE = re.compile(
        r"\b(urgent|immediately|act now|verify now|final notice|last warning)\b",
        re.IGNORECASE,
    )

    CREDENTIAL_RE = re.compile(
        r"\b(password|pin|otp|cvv|security code|login)\b",
        re.IGNORECASE,
    )

    FINANCIAL_RE = re.compile(
        r"\b(wire transfer|bank transfer|payment required|invoice attached)\b",
        re.IGNORECASE,
    )

    AUTHORITY_RE = re.compile(
        r"\b(fbi|irs|court order|tax authority|tra)\b",
        re.IGNORECASE,
    )

    PRIZE_RE = re.compile(
        r"\b(congratulations|you won|lottery|jackpot|reward)\b",
        re.IGNORECASE,
    )

    GENERIC_GREETING_RE = re.compile(
        r"Dear\s+(Customer|User|Member|Client)",
        re.IGNORECASE,
    )

    FEAR_RE = re.compile(
        r"\b(account suspended|arrest|lawsuit|terminated)\b",
        re.IGNORECASE,
    )

    SECRECY_RE = re.compile(
        r"\b(confidential|keep this secret|do not share)\b",
        re.IGNORECASE,
    )

    CRYPTO_RE = re.compile(
        r"\b(bitcoin|crypto|wallet address|usdt|ethereum)\b",
        re.IGNORECASE,
    )

    # ========================================================
    # MAIN EXTRACTION
    # ========================================================

    def extract(self, parsed_email) -> FeatureSet:
        """
        Main extraction entry point.
        """

        fs = FeatureSet()

        try:
            self._extract_url_features(parsed_email, fs)
            self._extract_sender_features(parsed_email, fs)
            self._extract_auth_features(parsed_email, fs)
            self._extract_content_features(parsed_email, fs)
            self._extract_html_features(parsed_email, fs)
            self._extract_attachment_features(parsed_email, fs)
            self._extract_linguistic_features(parsed_email, fs)
            self._extract_legitimacy_features(parsed_email, fs)

        except Exception as exc:
            logger.error(f"[FeatureExtractor] {exc}", exc_info=True)

        return fs

    # ========================================================
    # URL FEATURES
    # ========================================================

    def _extract_url_features(self, pe, fs: FeatureSet):

        fs.url_count = len(pe.urls)
        fs.unique_domain_count = len(set(pe.unique_domains))

        for url in pe.urls:

            parsed = urlparse(url)
            host = parsed.netloc.lower()

            # IP URL
            if re.match(r"^\d{1,3}(\.\d{1,3}){3}$", host):
                fs.has_ip_url = True

            # Shortener
            if host in URL_SHORTENERS:
                fs.has_shortener = True

            # High risk TLD
            for tld in HIGH_RISK_TLDS:
                if host.endswith(tld):
                    fs.has_high_risk_tld = True

            # @ trick
            if "@" in url:
                fs.has_at_symbol_url = True

            # Punycode
            if "xn--" in host:
                fs.has_punycode = True

            # data URI
            if url.lower().startswith("data:text/html"):
                fs.has_data_uri = True

            # javascript URI
            if url.lower().startswith("javascript:"):
                fs.has_javascript_uri = True

            # Long URL
            if len(url) > 120:
                fs.has_long_url = True

            # Excessive subdomains
            if host.count(".") >= 4:
                fs.excessive_subdomains = True

        fs.link_mismatch_count = pe.link_text_mismatches

    # ========================================================
    # SENDER FEATURES
    # ========================================================

    def _extract_sender_features(self, pe, fs: FeatureSet):

        fs.sender_domain = pe.sender_domain

        # Free email provider
        if pe.sender_domain in FREE_EMAIL_PROVIDERS:
            fs.free_email_provider = True

        # Reply-To mismatch
        if pe.reply_to_domain and pe.sender_domain:
            if pe.reply_to_domain != pe.sender_domain:
                fs.reply_to_mismatch = True

        # Display-name mismatch
        sender_name = (pe.sender_name or "").lower()

        for brand, official_domain in KNOWN_BRANDS.items():
            if brand in sender_name:
                if not pe.sender_domain.endswith(official_domain):
                    fs.sender_name_domain_mismatch = True
                    break

        # Typosquatting
        for brand_domain in KNOWN_BRANDS.values():
            ratio = difflib.SequenceMatcher(
                None,
                pe.sender_domain,
                brand_domain,
            ).ratio()

            if 0.80 < ratio < 1.0:
                fs.typosquatting_detected = True
                fs.typosquatting_target = brand_domain
                break

        # Random sender local-part
        if pe.sender_email and "@" in pe.sender_email:
            local = pe.sender_email.split("@")[0]

            if len(local) >= 10 and re.match(r"^[a-z0-9]+$", local):
                fs.random_local_part = True

    # ========================================================
    # AUTH FEATURES
    # ========================================================

    def _extract_auth_features(self, pe, fs: FeatureSet):

        spf = (pe.spf_result or "").lower()

        fs.spf_pass = spf == "pass"
        fs.spf_fail = spf in ("fail", "softfail")

        fs.dkim_pass = pe.dkim_result == "pass"
        fs.dkim_missing = not pe.dkim_present

        fs.dmarc_fail = pe.dmarc_result == "fail"

        # Suspicious X-Mailer
        if pe.x_mailer:
            fs.suspicious_mailer = bool(
                SUSPICIOUS_MAILERS.search(pe.x_mailer)
            )

        # Message-ID checks
        fs.missing_message_id = not pe.has_message_id

        if pe.message_id:
            fs.malformed_message_id = not bool(
                re.match(r"^<[^>]+@[^>]+>$", pe.message_id)
            )

    # ========================================================
    # CONTENT FEATURES
    # ========================================================

    def _extract_content_features(self, pe, fs: FeatureSet):

        text = " ".join(filter(None, [
            pe.subject or "",
            pe.body_text or "",
            pe.body_text_from_html or "",
        ]))

        if not text:
            return

        urgency_matches = self.URGENCY_RE.findall(text)

        fs.urgency_detected = len(urgency_matches) > 0
        fs.urgency_count = len(urgency_matches)

        fs.credential_request = bool(
            self.CREDENTIAL_RE.search(text)
        )

        fs.financial_request = bool(
            self.FINANCIAL_RE.search(text)
        )

        fs.authority_impersonation = bool(
            self.AUTHORITY_RE.search(text)
        )

        fs.prize_scam_language = bool(
            self.PRIZE_RE.search(text)
        )

        fs.generic_greeting = bool(
            self.GENERIC_GREETING_RE.search(text)
        )

        fs.fear_language = bool(
            self.FEAR_RE.search(text)
        )

        fs.secrecy_language = bool(
            self.SECRECY_RE.search(text)
        )

        fs.crypto_language = bool(
            self.CRYPTO_RE.search(text)
        )

    # ========================================================
    # HTML FEATURES
    # ========================================================

    def _extract_html_features(self, pe, fs: FeatureSet):

        html = pe.body_html or ""

        fs.has_html = bool(html)

        if not html:
            return

        html_lower = html.lower()

        fs.has_script = bool(
            re.search(r"<\s*script", html_lower)
        )

        fs.has_iframe = bool(
            re.search(r"<\s*iframe", html_lower)
        )

        fs.has_meta_refresh = bool(
            re.search(r"http-equiv=['\"]refresh", html_lower)
        )

        fs.hidden_text = bool(
            re.search(
                r"display\s*:\s*none|visibility\s*:\s*hidden",
                html_lower,
            )
        )

        fs.html_entity_obfuscation = bool(
            re.search(r"(&#\d{2,4};){4,}", html)
        )

        fs.external_form_action = bool(pe.form_actions)
        fs.external_image_count = len(pe.external_image_domains)

    # ========================================================
    # ATTACHMENT FEATURES
    # ========================================================

    def _extract_attachment_features(self, pe, fs: FeatureSet):

        fs.attachment_count = len(pe.attachment_names)

        for filename in pe.attachment_names:

            name = filename.lower()

            if re.search(r"\.(exe|scr|js|vbs|bat|cmd|ps1)$", name):
                fs.dangerous_attachment = True

            if re.search(r"\.(docm|xlsm|pptm)$", name):
                fs.macro_attachment = True

            if re.search(r"\.(pdf|jpg|png|doc)\.(exe|js|scr)$", name):
                fs.double_extension_attachment = True

            if re.search(r"\.(zip|rar|7z|iso|img|lnk)$", name):
                fs.archive_attachment = True

            if re.search(r"\.html?$", name):
                fs.html_attachment = True

    # ========================================================
    # LINGUISTIC FEATURES
    # ========================================================

    def _extract_linguistic_features(self, pe, fs: FeatureSet):

        text = pe.body_text or pe.body_text_from_html or ""

        fs.body_entropy = pe.body_text_entropy
        fs.subject_entropy = pe.subject_entropy
        fs.word_count = pe.word_count

        # Excessive CAPS
        caps_words = re.findall(r"\b[A-Z]{5,}\b", text)

        if len(caps_words) >= 3:
            fs.excessive_caps = True

        # Excessive !!!
        if re.search(r"!{3,}", text):
            fs.excessive_exclamation = True

        # Invisible unicode
        if re.search(r"[\u200B-\u200F\uFEFF]", text):
            fs.invisible_unicode = True

    # ========================================================
    # LEGITIMACY FEATURES
    # ========================================================

    def _extract_legitimacy_features(self, pe, fs: FeatureSet):
        """
        Positive legitimacy signals.
        These reduce false positives.
        """

        fs.unsubscribe_header = pe.has_unsubscribe_header
        fs.list_id_header = pe.has_list_id
        fs.personally_addressed = pe.recipient_named

        fs.normal_send_time = (
            pe.send_hour_utc is not None
            and 6 <= pe.send_hour_utc <= 22
        )

        fs.has_plain_text_version = bool(
            pe.body_text and pe.body_html
        )

        if pe.sender_domain in {
            "google.com",
            "gmail.com",
            "microsoft.com",
            "outlook.com",
            "amazon.com",
            "apple.com",
            "crdbbank.com",
            "nmbbank.co.tz",
            "tra.go.tz",
        }:
            fs.known_provider = True

    # ========================================================
    # HELPERS
    # ========================================================

    @staticmethod
    def shannon_entropy(text: str) -> float:
        """
        Calculates Shannon entropy.
        Useful for detecting random strings.
        """

        if not text:
            return 0.0

        frequency = {}

        for char in text:
            frequency[char] = frequency.get(char, 0) + 1

        entropy = 0.0
        length = len(text)

        for count in frequency.values():
            probability = count / length
            entropy -= probability * math.log2(probability)

        return entropy
