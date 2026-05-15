"""
backend/engine/email_parser.py
================================
Professional MIME email parser for PhishGuard v2.

RESPONSIBILITIES
----------------
1. Parse raw RFC-2822 email strings (parse_raw)
2. Parse individual field submissions from the API (parse_fields)
3. Populate a rich ParsedEmail dataclass with ALL features needed
   by the FeatureEngine, RuleEngine, CorrelationEngine, and LegitimacyEngine

DESIGN PRINCIPLES
-----------------
- Never crash — every method catches its own exceptions
- Populate as many fields as possible for better detection accuracy
- Compute derived fields (entropy, word count, URL analysis) once here
  so downstream engines don't duplicate work
- Keep TRUSTED_DOMAINS and SUSPICIOUS_TLDS here as the single source of truth
"""

import re
import math
import email
import email.utils
import logging

from dataclasses import dataclass, field
from typing import List, Dict, Optional
from urllib.parse import urlparse

from bs4 import BeautifulSoup

logger = logging.getLogger(__name__)


# ============================================================
# CONSTANTS — single source of truth for the whole engine
# ============================================================

# Domains whose emails should be treated with lower suspicion by default.
# Include common major providers AND Tanzanian institutions since this
# system is deployed in a Tanzanian context.
#
# NOTE: subdomain detection is handled in _parse_sender_string — any domain
# that ENDS WITH one of these (e.g. cse.udsm.ac.tz ends with .udsm.ac.tz)
# is also marked as trusted.
TRUSTED_DOMAINS = frozenset([
    # Major international providers
    "google.com", "gmail.com", "googlemail.com",
    "microsoft.com", "outlook.com", "live.com", "hotmail.com",
    "apple.com", "icloud.com",
    "amazon.com", "amazon.co.uk",
    "paypal.com",
    # Tanzanian banks
    "crdbbank.com", "crdb.co.tz",
    "nmbbank.co.tz",
    "equitybank.co.tz",
    "kcbgroup.com",
    # Tanzanian government
    "tra.go.tz",
    # Tanzanian universities (public)
    "udsm.ac.tz",     # University of Dar es Salaam
    "udom.ac.tz",     # University of Dodoma
    "mzumbe.ac.tz",   # Mzumbe University
    "must.ac.tz",     # Moshi University of Science and Technology
    "muhas.ac.tz",    # Muhimbili University of Health and Allied Sciences
    "suza.ac.tz",     # State University of Zanzibar
    "open.ac.tz",     # The Open University of Tanzania
    "tuma.ac.tz",     # Tumaini University
    # Tanzanian schools / orgs use .ac.tz and .or.tz — we trust the TLD suffix
    # rather than enumerate every institution; covered by subdomain check
])

# TLDs associated with high phishing abuse rates (from APWG and other sources)
SUSPICIOUS_TLDS = frozenset([
    ".xyz", ".top", ".click", ".tk", ".ml", ".ga", ".cf",
    ".gq", ".pw", ".loan", ".win", ".bid", ".download", ".work",
    ".ru", ".cn",
])

# URL shortener domains that hide real destinations
URL_SHORTENERS = frozenset([
    "bit.ly", "tinyurl.com", "goo.gl", "ow.ly", "t.co",
    "cutt.ly", "rb.gy", "short.link", "is.gd", "buff.ly",
    "tiny.cc", "lnkd.in",
])

# File extensions that can execute code when opened
DANGEROUS_EXTENSIONS = frozenset([
    ".exe", ".js", ".vbs", ".bat", ".cmd", ".scr", ".ps1",
    ".jar", ".msi", ".dmg", ".app", ".lnk", ".iso", ".img",
    ".docm", ".xlsm", ".pptm", ".dotm", ".xlam",
])

# Regex: extract http(s) URLs from text
URL_REGEX = re.compile(r"https?://[^\s<>\"'\]]+", re.IGNORECASE)

# Regex: match IPv4 address as the URL hostname
IP_HOST_RE = re.compile(r"^\d{1,3}(\.\d{1,3}){3}(:\d+)?$")

# Regex: detect hexadecimal IP (0xC0A80001)
HEX_IP_RE = re.compile(r"^0x[a-fA-F0-9]{2,}$", re.IGNORECASE)


# ============================================================
# PARSED EMAIL DATACLASS
# ============================================================

@dataclass
class ParsedEmail:
    """
    Complete representation of a parsed email.

    Every field consumed by FeatureEngine, RuleEngine, CorrelationEngine,
    or LegitimacyEngine lives here, computed once at parse time.
    """

    # ----------------------------------------------------------
    # IDENTITY
    # ----------------------------------------------------------
    sender_raw: str = ""          # Raw From: header value
    sender_email: str = ""        # Normalised email address
    sender_name: str = ""         # Display name portion
    sender_domain: str = ""       # Domain part of sender_email
    sender_tld: str = ""          # TLD of sender domain (e.g. ".com")
    reply_to_email: str = ""      # Reply-To address
    reply_to_domain: str = ""     # Domain of Reply-To

    # ----------------------------------------------------------
    # SUBJECT
    # ----------------------------------------------------------
    subject: str = ""
    subject_has_re_fwd: bool = False  # Subject starts with Re: or Fwd:

    # ----------------------------------------------------------
    # BODY
    # ----------------------------------------------------------
    body_text: str = ""           # Plain-text body
    body_html: str = ""           # Raw HTML body
    visible_text: str = ""        # Visible text extracted from HTML
    body_text_from_html: str = "" # Alias for visible_text (compat)

    # ----------------------------------------------------------
    # URLS
    # ----------------------------------------------------------
    urls: List[str] = field(default_factory=list)          # All extracted URLs
    unique_domains: List[str] = field(default_factory=list)  # Unique URL domains
    url_count: int = 0             # len(urls) — convenience

    # URL risk flags (pre-computed to avoid duplicate work)
    has_ip_url: bool = False
    has_hex_ip_url: bool = False
    has_shortener: bool = False
    has_suspicious_tld: bool = False
    has_at_in_url: bool = False
    has_punycode_url: bool = False
    has_data_uri: bool = False
    has_js_uri: bool = False
    has_excessive_subdomains: bool = False
    max_url_length: int = 0

    # Link text vs href mismatch analysis
    href_pairs: List[Dict] = field(default_factory=list)
    link_text_mismatches: int = 0

    # ----------------------------------------------------------
    # HEADERS
    # ----------------------------------------------------------
    headers: Dict[str, str] = field(default_factory=dict)
    message_id: str = ""
    valid_message_id: bool = False   # Well-formed <id@domain>
    has_message_id: bool = False     # Header present at all
    x_mailer: str = ""               # X-Mailer value
    x_priority: str = ""             # X-Priority value
    date_header: str = ""            # Date: header raw value
    has_mime_version: bool = False   # MIME-Version header present

    # ----------------------------------------------------------
    # AUTHENTICATION
    # ----------------------------------------------------------
    # String result ("pass" / "fail" / "softfail" / "none" / "")
    spf_result: str = ""
    dkim_result: str = ""
    dmarc_result: str = ""

    # Boolean shortcuts (kept for backward compatibility)
    spf_pass: bool = False
    dkim_pass: bool = False
    dmarc_pass: bool = False
    dkim_present: bool = False   # DKIM-Signature header exists

    # ----------------------------------------------------------
    # HTML FEATURES
    # ----------------------------------------------------------
    has_script: bool = False
    has_iframe: bool = False
    has_form: bool = False
    has_meta_refresh: bool = False
    hidden_text_count: int = 0       # Elements with display:none / visibility:hidden
    inline_style_count: int = 0      # Elements with inline style=""
    html_nesting_depth: int = 0      # Rough nesting depth estimate
    external_image_domains: List[str] = field(default_factory=list)
    form_actions: List[str] = field(default_factory=list)

    # ----------------------------------------------------------
    # ATTACHMENTS
    # ----------------------------------------------------------
    attachment_names: List[str] = field(default_factory=list)
    has_dangerous_attachment: bool = False   # Any executable/macro extension

    # ----------------------------------------------------------
    # LEGITIMACY SIGNALS
    # ----------------------------------------------------------
    trusted_domain: bool = False          # Sender is in TRUSTED_DOMAINS
    personalised_email: bool = False      # Contains "Dear FirstName"
    recipient_named: bool = False         # Alias for personalised_email
    has_unsubscribe_header: bool = False  # List-Unsubscribe header present
    has_list_id: bool = False             # List-ID header present

    # ----------------------------------------------------------
    # TIMING
    # ----------------------------------------------------------
    send_hour_utc: Optional[int] = None   # Hour (0-23) the email was sent

    # ----------------------------------------------------------
    # LINGUISTIC METRICS
    # ----------------------------------------------------------
    body_entropy: float = 0.0        # Shannon entropy of body_text
    body_text_entropy: float = 0.0   # Alias for body_entropy
    subject_entropy: float = 0.0
    word_count: int = 0
    avg_word_length: float = 0.0


# ============================================================
# EMAIL PARSER
# ============================================================

class EmailParser:
    """
    Parses raw RFC-2822 email strings or individual field submissions
    into a comprehensive ParsedEmail dataclass.
    """

    # ----------------------------------------------------------
    # PUBLIC API
    # ----------------------------------------------------------

    def parse_raw(self, raw_email: str) -> ParsedEmail:
        """Parse a complete raw RFC-2822 email string."""
        parsed = ParsedEmail()
        try:
            msg = email.message_from_string(raw_email)
            self._extract_headers(msg, parsed)
            self._extract_sender(msg, parsed)
            self._extract_body(msg, parsed)
        except Exception as exc:
            logger.warning(f"[Parser] parse_raw failed: {exc}")

        # _post_process is also wrapped so any individual failure
        # is logged but never crashes the caller
        try:
            self._post_process(parsed)
        except Exception as exc:
            logger.warning(f"[Parser] post_process failed in parse_raw: {exc}")

        return parsed

    def parse_fields(
        self,
        sender: str = "",
        subject: str = "",
        body_text: str = "",
        body_html: str = "",
        headers: str = "",
        recipient: str = "",
    ) -> ParsedEmail:
        """Parse from individual form fields (non-raw submission path)."""
        parsed = ParsedEmail()
        try:
            parsed.subject   = subject   or ""
            parsed.body_text = body_text or ""
            parsed.body_html = body_html or ""
            self._parse_sender_string(sender or "", parsed)
            self._parse_header_block(headers or "", parsed)
        except Exception as exc:
            logger.warning(f"[Parser] parse_fields failed: {exc}")

        try:
            self._post_process(parsed)
        except Exception as exc:
            logger.warning(f"[Parser] post_process failed in parse_fields: {exc}")

        return parsed

    # ----------------------------------------------------------
    # HEADER EXTRACTION
    # ----------------------------------------------------------

    def _extract_headers(self, msg, parsed: ParsedEmail) -> None:
        """Extract all headers from a parsed email.Message object."""
        # Build a lowercase header dict for easy lookup
        parsed.headers = {k.lower(): v for k, v in msg.items()}

        parsed.subject = msg.get("Subject", "") or ""
        parsed.message_id = msg.get("Message-ID", "") or ""
        parsed.has_message_id = bool(parsed.message_id.strip())
        parsed.valid_message_id = bool(
            re.match(r"^<[^>]+@[^>]+>$", parsed.message_id.strip())
        )

        # X-Mailer: identifies the sending software (phishers use bulk tools)
        parsed.x_mailer = msg.get("X-Mailer", "") or ""

        # X-Priority: 1 = Highest (manipulates perceived urgency)
        parsed.x_priority = msg.get("X-Priority", "") or ""

        # Date: used to detect off-hours sends
        parsed.date_header = msg.get("Date", "") or ""

        # MIME-Version: present in all legitimate HTML emails
        parsed.has_mime_version = "mime-version" in parsed.headers

        # Reply-To domain: divergence from From domain is a strong signal
        reply_to_raw = msg.get("Reply-To", "") or ""
        if reply_to_raw:
            parsed.reply_to_email, parsed.reply_to_domain = (
                self._extract_email_domain(reply_to_raw)
            )

        # Legitimacy newsletter headers
        parsed.has_unsubscribe_header = (
            "list-unsubscribe" in parsed.headers
        )
        parsed.has_list_id = "list-id" in parsed.headers

        # Authentication results (single header that carriers add)
        self._extract_authentication(parsed)

        # DKIM-Signature: its mere presence is checked
        parsed.dkim_present = "dkim-signature" in parsed.headers

    def _parse_header_block(self, header_text: str, parsed: ParsedEmail) -> None:
        """Parse a raw header block string (from the fields submission path)."""
        for line in header_text.splitlines():
            if ":" in line:
                key, _, value = line.partition(":")
                k = key.strip().lower()
                v = value.strip()
                parsed.headers[k] = v

        # Re-extract computed values from the populated headers dict
        parsed.message_id = parsed.headers.get("message-id", "")
        parsed.has_message_id = bool(parsed.message_id.strip())
        parsed.valid_message_id = bool(
            re.match(r"^<[^>]+@[^>]+>$", parsed.message_id.strip())
        )
        parsed.x_mailer = parsed.headers.get("x-mailer", "")
        parsed.x_priority = parsed.headers.get("x-priority", "")
        parsed.date_header = parsed.headers.get("date", "")
        parsed.has_mime_version = "mime-version" in parsed.headers
        parsed.has_unsubscribe_header = "list-unsubscribe" in parsed.headers
        parsed.has_list_id = "list-id" in parsed.headers
        parsed.dkim_present = "dkim-signature" in parsed.headers

        reply_to_raw = parsed.headers.get("reply-to", "")
        if reply_to_raw:
            parsed.reply_to_email, parsed.reply_to_domain = (
                self._extract_email_domain(reply_to_raw)
            )

        self._extract_authentication(parsed)

    # ----------------------------------------------------------
    # AUTHENTICATION
    # ----------------------------------------------------------

    def _extract_authentication(self, parsed: ParsedEmail) -> None:
        """
        Parse Authentication-Results header for SPF / DKIM / DMARC verdicts.
        Also checks Received-SPF for SPF result as a fallback.
        """
        auth = parsed.headers.get("authentication-results", "").lower()

        # SPF — also check Received-SPF as a fallback
        received_spf = parsed.headers.get("received-spf", "").lower()
        spf_src = auth if "spf=" in auth else received_spf

        if "spf=pass" in spf_src:
            parsed.spf_result = "pass"
        elif "spf=fail" in spf_src:
            parsed.spf_result = "fail"
        elif "spf=softfail" in spf_src:
            parsed.spf_result = "softfail"
        elif "spf=neutral" in spf_src:
            parsed.spf_result = "neutral"
        else:
            parsed.spf_result = ""

        parsed.spf_pass = parsed.spf_result == "pass"

        # DKIM
        if "dkim=pass" in auth:
            parsed.dkim_result = "pass"
        elif "dkim=fail" in auth:
            parsed.dkim_result = "fail"
        else:
            parsed.dkim_result = ""

        parsed.dkim_pass = parsed.dkim_result == "pass"

        # DMARC
        if "dmarc=pass" in auth:
            parsed.dmarc_result = "pass"
        elif "dmarc=fail" in auth:
            parsed.dmarc_result = "fail"
        else:
            parsed.dmarc_result = ""

        parsed.dmarc_pass = parsed.dmarc_result == "pass"

    # ----------------------------------------------------------
    # SENDER EXTRACTION
    # ----------------------------------------------------------

    def _extract_sender(self, msg, parsed: ParsedEmail) -> None:
        """Extract From: header from a parsed email.Message."""
        raw = msg.get("From", "") or ""
        parsed.sender_raw = raw
        self._parse_sender_string(raw, parsed)

    def _parse_sender_string(self, sender: str, parsed: ParsedEmail) -> None:
        """Parse a raw From: string into email, name, domain, tld."""
        if not sender:
            return

        parsed.sender_raw = sender

        # Extract <email@domain> form first, fallback to bare address
        match = re.search(r"<([^>]+)>", sender)
        if match:
            parsed.sender_email = match.group(1).strip().lower()
        else:
            parsed.sender_email = sender.strip().lower()

        # Remove angle-brackets and the email to get the display name
        parsed.sender_name = (
            re.sub(r"<[^>]*>", "", sender).strip().strip('"').strip("'")
        )

        # Split domain from local-part
        if "@" in parsed.sender_email:
            parsed.sender_domain = parsed.sender_email.split("@")[-1].strip()

        # Compute TLD
        if parsed.sender_domain and "." in parsed.sender_domain:
            parsed.sender_tld = "." + parsed.sender_domain.rsplit(".", 1)[-1]

        # Check trusted domain — also matches any SUBDOMAIN of a trusted domain.
        # e.g. cse.udsm.ac.tz → ends with .udsm.ac.tz → trusted.
        # This prevents the typosquatting check from firing on legitimate
        # sub-organisation addresses like hod@cse.udsm.ac.tz.
        d = parsed.sender_domain
        if d in TRUSTED_DOMAINS or any(
            d.endswith("." + t) for t in TRUSTED_DOMAINS
        ):
            parsed.trusted_domain = True

    @staticmethod
    def _extract_email_domain(raw: str):
        """Return (email_address, domain) from a raw From/Reply-To string."""
        match = re.search(r"<([^>]+)>", raw)
        addr = match.group(1).strip().lower() if match else raw.strip().lower()
        domain = addr.split("@")[-1] if "@" in addr else ""
        return addr, domain

    # ----------------------------------------------------------
    # BODY EXTRACTION
    # ----------------------------------------------------------

    def _extract_body(self, msg, parsed: ParsedEmail) -> None:
        """Walk the MIME tree to extract text/plain, text/html, attachments."""
        if msg.is_multipart():
            for part in msg.walk():
                content_type = part.get_content_type()
                disposition = str(part.get("Content-Disposition", ""))

                # Attachments: record filename only
                if "attachment" in disposition:
                    filename = part.get_filename()
                    if filename:
                        parsed.attachment_names.append(filename)
                    continue

                payload = self._decode_payload(part)

                if content_type == "text/plain":
                    parsed.body_text += payload
                elif content_type == "text/html":
                    parsed.body_html += payload
        else:
            # Single-part message: treat as plain text
            parsed.body_text = self._decode_payload(msg)

    @staticmethod
    def _decode_payload(part) -> str:
        """Decode a MIME part payload to a Python string."""
        try:
            raw = part.get_payload(decode=True)
            if not raw:
                return ""
            charset = part.get_content_charset() or "utf-8"
            return raw.decode(charset, errors="replace")
        except Exception:
            return ""

    # ----------------------------------------------------------
    # HTML ANALYSIS
    # ----------------------------------------------------------

    def _parse_html(self, parsed: ParsedEmail) -> None:
        """
        Analyse the HTML body with BeautifulSoup.
        Extracts: visible text, form info, image domains, href mismatches,
        meta-refresh, hidden text count, inline style density.
        """
        try:
            soup = BeautifulSoup(parsed.body_html, "html.parser")

            # Visible text (decoded entities, no tags)
            parsed.visible_text = soup.get_text(separator=" ", strip=True)
            parsed.body_text_from_html = parsed.visible_text  # alias

            # Basic HTML indicators
            parsed.has_form = bool(soup.find("form"))
            parsed.has_script = bool(soup.find("script"))
            parsed.has_iframe = bool(soup.find("iframe"))

            # Meta http-equiv="refresh" → auto-redirect to phishing page
            for meta in soup.find_all("meta"):
                if meta.get("http-equiv", "").lower() == "refresh":
                    parsed.has_meta_refresh = True
                    break

            # Hidden text: display:none / visibility:hidden / font-size:0
            hidden_re = re.compile(
                r"display\s*:\s*none|visibility\s*:\s*hidden|font-size\s*:\s*0",
                re.IGNORECASE,
            )
            hidden_tags = [
                t for t in soup.find_all(True)
                if hidden_re.search(t.get("style", ""))
            ]
            parsed.hidden_text_count = len(hidden_tags)

            # Inline style density: number of elements that carry style=""
            parsed.inline_style_count = len(soup.find_all(True, style=True))

            # Rough HTML nesting depth: count total tags as a proxy
            # (deep nesting is a phishing kit characteristic)
            parsed.html_nesting_depth = len(soup.find_all(True))

            # External image domains: for tracking pixel detection
            img_domains: set = set()
            for img in soup.find_all("img", src=True):
                src = img["src"]
                if src.startswith("http"):
                    try:
                        domain = urlparse(src).netloc.lower()
                        if domain:
                            img_domains.add(domain)
                    except Exception:
                        pass
            parsed.external_image_domains = list(img_domains)

            # Form action URLs: external form = credential harvesting
            for form in soup.find_all("form"):
                action = form.get("action", "")
                if action and action.startswith("http"):
                    parsed.form_actions.append(action[:500])

            # Link text vs href domain mismatch: classic visual deception
            href_pairs = []
            for anchor in soup.find_all("a", href=True):
                href = anchor["href"]
                text = anchor.get_text(strip=True)
                if not href.startswith("http"):
                    continue
                try:
                    href_domain = urlparse(href).netloc.lower().lstrip("www.")
                    if not href_domain:
                        continue

                    # Extract domain-like token from visible link text
                    text_domain = ""
                    url_in_text = re.search(r"https?://([^\s/]+)", text)
                    if url_in_text:
                        text_domain = url_in_text.group(1).lower().lstrip("www.")
                    elif re.match(r"^[a-z0-9\-\.]+\.[a-z]{2,}$", text.lower()):
                        text_domain = text.lower().lstrip("www.")

                    if text_domain and text_domain != href_domain:
                        href_pairs.append({
                            "text": text[:120],
                            "text_domain": text_domain,
                            "href": href[:300],
                            "href_domain": href_domain,
                        })
                except Exception:
                    pass

            parsed.href_pairs = href_pairs
            parsed.link_text_mismatches = len(href_pairs)

        except Exception as exc:
            logger.warning(f"[Parser] _parse_html failed: {exc}")

    # ----------------------------------------------------------
    # URL ANALYSIS
    # ----------------------------------------------------------

    def _extract_urls(self, parsed: ParsedEmail) -> None:
        """
        Extract all http(s) URLs from plain text, visible HTML text,
        AND raw HTML (to catch href/src attributes inside tags).
        Then compute URL-level risk flags in a single pass.
        """
        # Include body_html so href="https://..." attributes are captured.
        # URL_REGEX stops at whitespace or quote chars, so it correctly
        # terminates at the closing quote of an href attribute.
        text = " ".join(filter(None, [
            parsed.body_text,
            parsed.visible_text,
            parsed.body_html,     # catches href= / src= attributes
        ]))
        raw_urls = URL_REGEX.findall(text)

        clean_urls: list = []
        domains_seen: set = set()

        for url in raw_urls:
            try:
                parsed_url = urlparse(url)
                host = parsed_url.netloc.lower()
                if not host:
                    continue

                # Normalise to scheme://host/path
                normalised = (
                    parsed_url.scheme.lower()
                    + "://"
                    + host
                    + parsed_url.path
                )
                clean_urls.append(normalised)
                domains_seen.add(host.lstrip("www."))

                # ── Risk flag computation ──────────────────────────────

                # Bare IPv4 address as hostname
                if IP_HOST_RE.match(host.split(":")[0]):
                    parsed.has_ip_url = True

                # Hexadecimal IP (e.g. http://0xC0A80001/)
                if HEX_IP_RE.match(host):
                    parsed.has_hex_ip_url = True

                # URL shortener hides the real destination
                bare_host = host.split(":")[0]
                if bare_host in URL_SHORTENERS:
                    parsed.has_shortener = True

                # High-abuse TLD
                tld = "." + host.rsplit(".", 1)[-1] if "." in host else ""
                if tld in SUSPICIOUS_TLDS:
                    parsed.has_suspicious_tld = True

                # @ trick: everything before @ is ignored by browsers
                if "@" in url:
                    parsed.has_at_in_url = True

                # Punycode (IDN homograph attack: xn--pаypal.com)
                if "xn--" in host:
                    parsed.has_punycode_url = True

                # Data URI embeds an entire HTML page
                if url.lower().startswith("data:text/html"):
                    parsed.has_data_uri = True

                # JavaScript URI executes code on click
                if url.lower().startswith("javascript:"):
                    parsed.has_js_uri = True

                # Excessive subdomains simulate trusted-looking paths
                if host.count(".") >= 4:
                    parsed.has_excessive_subdomains = True

                # Track longest URL
                if len(url) > parsed.max_url_length:
                    parsed.max_url_length = len(url)

            except Exception:
                continue

        # Deduplicate while preserving order
        parsed.urls = list(dict.fromkeys(clean_urls))
        parsed.unique_domains = list(domains_seen)
        parsed.url_count = len(parsed.urls)

    # ----------------------------------------------------------
    # PERSONALISATION
    # ----------------------------------------------------------

    # Generic salutation words that look like names but are NOT personal names.
    # Include plurals, role titles, and common group addresses so that
    # "Dear Members", "Dear Staff", "Dear Teacher", "Dear Students" etc.
    # do NOT trigger the personalised-greeting legitimacy deduction — those
    # are mass-addressed emails, not targeted personal ones.
    _GENERIC_SALUTATION_WORDS = frozenset([
        # Generic nouns (singular)
        "customer", "user", "member", "client", "subscriber",
        "sir", "madam", "friend", "team", "valued", "dear",
        "account", "holder", "applicant", "candidate", "partner",
        "taxpayer", "resident", "investor", "employee", "colleague",
        # Plurals (mass emails always use plurals)
        "customers", "users", "members", "clients", "subscribers",
        "employees", "colleagues", "partners", "residents",
        "students", "staff", "teachers", "parents", "managers",
        # Role/title words
        "teacher", "professor", "doctor", "principal",
        "director", "officer", "manager",
        # Lottery / prize scam salutations
        "winner", "beneficiary", "participant", "recipient",
        "reader", "patron",
    ])

    def _detect_personalisation(self, parsed: ParsedEmail) -> None:
        """
        Detect whether the email addresses the recipient by a real personal name.
        Mass phishing campaigns use generic titles ('Dear Customer') while
        legitimate emails and targeted attacks use actual names ('Dear John').

        This is a LEGITIMACY signal, so we must NOT count generic titles.
        'Dear Customer' / 'Dear User' → NOT personalised.
        'Dear John Msangi' / 'Hi Sarah' → personalised.
        """
        text = parsed.visible_text or parsed.body_text
        if not text:
            return

        # Match: (Dear|Hello|Hi) followed by a capitalised word (a name)
        m = re.search(
            r"\b(Dear|Hello|Hi)\s+([A-Z][a-z]{1,30})\b",
            text,
        )
        if m:
            # Reject if the matched word is a common generic salutation
            name_word = m.group(2).lower()
            if name_word not in self._GENERIC_SALUTATION_WORDS:
                parsed.personalised_email = True
                parsed.recipient_named = True

    # ----------------------------------------------------------
    # ATTACHMENT RISK
    # ----------------------------------------------------------

    def _check_dangerous_attachments(self, parsed: ParsedEmail) -> None:
        """Flag if any attachment has a dangerous or executable extension."""
        for filename in parsed.attachment_names:
            lower = filename.lower()
            for ext in DANGEROUS_EXTENSIONS:
                if lower.endswith(ext):
                    parsed.has_dangerous_attachment = True
                    return  # One is enough to flag

    # ----------------------------------------------------------
    # TIMING
    # ----------------------------------------------------------

    def _extract_send_hour(self, parsed: ParsedEmail) -> None:
        """Parse the Date: header to extract the UTC hour of sending."""
        if not parsed.date_header:
            return
        try:
            dt = email.utils.parsedate_to_datetime(parsed.date_header)
            parsed.send_hour_utc = dt.utctimetuple().tm_hour
        except Exception:
            pass

    # ----------------------------------------------------------
    # SUBJECT ANALYSIS
    # ----------------------------------------------------------

    def _analyse_subject(self, parsed: ParsedEmail) -> None:
        """
        Detect Re:/Fwd: prefix (a legitimacy signal — part of a real thread)
        and compute subject entropy.
        """
        subj = (parsed.subject or "").strip()
        if re.match(r"^(Re:|Fwd:|FW:)", subj, re.IGNORECASE):
            parsed.subject_has_re_fwd = True

        parsed.subject_entropy = self._shannon_entropy(subj)

    # ----------------------------------------------------------
    # ENTROPY & LINGUISTIC METRICS
    # ----------------------------------------------------------

    def _compute_entropy(self, parsed: ParsedEmail) -> None:
        """
        Compute Shannon entropy of the body text (limited to 2000 chars).
        High entropy = possibly random/encrypted content.
        """
        text = parsed.body_text[:2_000] or parsed.visible_text[:2_000]
        parsed.body_entropy = self._shannon_entropy(text)
        parsed.body_text_entropy = parsed.body_entropy  # alias

    def _compute_linguistic_metrics(self, parsed: ParsedEmail) -> None:
        """Count words and compute average word length."""
        text = parsed.body_text or parsed.visible_text
        if not text:
            return
        words = re.findall(r"\b\w+\b", text)
        parsed.word_count = len(words)
        if words:
            parsed.avg_word_length = sum(len(w) for w in words) / len(words)

    @staticmethod
    def _shannon_entropy(text: str) -> float:
        """Shannon entropy: measures randomness of character distribution."""
        if not text:
            return 0.0
        freq: dict = {}
        for ch in text:
            freq[ch] = freq.get(ch, 0) + 1
        length = len(text)
        entropy = 0.0
        for count in freq.values():
            p = count / length
            entropy -= p * math.log2(p)
        return round(entropy, 3)

    # ----------------------------------------------------------
    # POST-PROCESS COORDINATOR
    # ----------------------------------------------------------

    def _post_process(self, parsed: ParsedEmail) -> None:
        """
        Run all computed-field methods after the raw content is populated.
        Order matters: HTML must be parsed before URL extraction (visible_text).
        """
        # Parse HTML to get visible_text + HTML features
        if parsed.body_html:
            self._parse_html(parsed)

        # Extract and analyse URLs from text + visible HTML text
        self._extract_urls(parsed)

        # Personalisation (depends on visible_text)
        self._detect_personalisation(parsed)

        # Attachment risk flags
        self._check_dangerous_attachments(parsed)

        # Subject analysis
        self._analyse_subject(parsed)

        # Timing
        self._extract_send_hour(parsed)

        # Entropy + linguistic metrics
        self._compute_entropy(parsed)
        self._compute_linguistic_metrics(parsed)


# ── Module-level helpers (exported for tests and external use) ────────────────

def _shannon_entropy(text: str) -> float:
    """Module-level wrapper — same as EmailParser._shannon_entropy."""
    return EmailParser._shannon_entropy(text)


def _normalise_url(url: str) -> str:
    """
    Normalise a URL to lowercase scheme+host, preserving path case.
    Exported for tests that validate URL normalisation behaviour.
    """
    try:
        p = urlparse(url)
        return p.scheme.lower() + "://" + p.netloc.lower() + p.path
    except Exception:
        return url.lower()
