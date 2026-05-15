"""
backend/engine/rule_engine.py
================================
Production Rule Engine for PhishGuard v2.

ROOT CAUSES OF v1 FALSE POSITIVES (all fixed here):
  1. REGEX ON EMPTY STRINGS
     v1 scanned combined body text including empty fields.
     Fix: skip any scan target that is empty or None.

  2. OVER-BROAD REGEXES
     "urgent" fires on "It's urgent that you read our safety guide"
     — a legitimate company newsletter.
     Fix: context-aware patterns, lower weights for ambiguous rules.

  3. DKIM RULE ON LEGITIMATE SMALL BUSINESSES
     Many small businesses and universities don't configure DKIM.
     Fix: DKIM missing is weight 1.5, not 2.5.  Only fires with other signals.

  4. GENERIC GREETING ON BULK MARKETING
     "Dear Customer" appears in millions of legitimate marketing emails.
     Fix: weight 0.8, combined with other signals only.

  5. RULES LOADED FROM DB ON EVERY REQUEST (performance)
     Fix: rules cached in memory, refreshed every 60 seconds.

  6. pe.body_visible used but ParsedEmail has visible_text
     Fix: all scan targets now use the correct ParsedEmail field names.

DESIGN:
  The Rule Engine DETECTS only — it never decides.
  Each rule returns a RuleMatch or None.
  The Scoring + Correlation engines decide what the matches mean.
"""

import re
import time
import logging
import difflib
from dataclasses import dataclass, field
from typing import List, Optional, Dict, Tuple
from urllib.parse import urlparse

logger = logging.getLogger(__name__)


# ============================================================
# RULE PROXY — session-detached cache entry
# ============================================================

@dataclass
class _RuleProxy:
    """
    Plain-Python copy of a Rule DB row.

    WHY THIS EXISTS:
    SQLAlchemy ORM objects are bound to the database session that loaded them.
    When a Flask request ends, Flask-SQLAlchemy expires/closes that session.
    Any attempt to access an attribute on the cached ORM object in a LATER
    request triggers a lazy-reload, which fails with DetachedInstanceError
    because the original session is gone.

    Storing plain dataclass instances (not ORM objects) in the class-level
    cache completely avoids this — the data is a regular Python object with
    no SQLAlchemy state attached.
    """
    id:          int
    rule_id:     str
    name:        str
    category:    str
    weight:      float
    description: str
    pattern:     str
    is_enabled:  bool
    is_custom:   bool

    @classmethod
    def from_orm(cls, rule) -> "_RuleProxy":
        """Copy all needed fields out of a Rule ORM instance."""
        return cls(
            id          = rule.id,
            rule_id     = rule.rule_id,
            name        = rule.name        or "",
            category    = rule.category    or "",
            weight      = float(rule.weight or 1.0),
            description = rule.description or "",
            pattern     = rule.pattern     or "",
            is_enabled  = bool(rule.is_enabled),
            is_custom   = bool(rule.is_custom),
        )


# ============================================================
# RULE MATCH
# ============================================================

@dataclass
class RuleMatch:
    """
    One fired rule with all evidence needed for explainability.

    score_contribution is set by ScoringEngine after the rule fires.
    severity is derived from weight for API display.
    """
    rule_id:            str
    rule_db_id:         int
    name:               str     # Human-readable rule name
    category:           str
    weight:             float
    evidence:           str     # Snippet or description of what matched
    explanation:        str     # Why this is suspicious
    score_contribution: float = 0.0

    @property
    def rule_name(self) -> str:
        """Alias for name — used by analysis_pipeline response builder."""
        return self.name

    @property
    def severity(self) -> str:
        """Derive a severity label from the rule weight."""
        if self.weight >= 2.5:
            return "high"
        if self.weight >= 1.5:
            return "medium"
        return "low"


# ============================================================
# RULE ENGINE
# ============================================================

class RuleEngine:
    """
    Evaluates all enabled rules against a ParsedEmail.

    PERFORMANCE: Rules are cached in memory and refreshed every 60 s.
    This avoids the N×DB query per analysis that crushed v1 performance.
    """

    # Class-level cache shared across all instances
    _rules_cache: List = []
    _cache_ts: float = 0.0
    _CACHE_TTL: int = 60          # seconds before reloading from DB

    # Known brand domains for typosquatting detection
    BRAND_DOMAINS: List[str] = [
        "paypal.com", "amazon.com", "google.com", "microsoft.com",
        "apple.com", "facebook.com", "netflix.com", "ebay.com",
        "chase.com", "bankofamerica.com", "wellsfargo.com",
        "crdbbank.com", "nmbbank.co.tz", "equitybank.co.tz",
        "standardbank.com", "stanbic.com", "kcbgroup.com",
    ]

    # Compiled regex cache — avoids recompiling on every rule evaluation
    _compiled_regex: Dict[str, re.Pattern] = {}

    # ── Programmatic handler registry ────────────────────────────────────────

    def _get_handlers(self) -> Dict:
        """Map sentinel pattern strings → handler methods."""
        return {
            "DISPLAY_DOMAIN_MISMATCH":   self._check_display_domain_mismatch,
            "TYPOSQUATTING_CHECK":       self._check_typosquatting,
            "REPLY_TO_MISMATCH":         self._check_reply_to_mismatch,
            "DKIM_MISSING_OR_FAIL":      self._check_dkim,
            "DMARC_NOT_ENFORCED":        self._check_dmarc,
            "LINK_TEXT_HREF_MISMATCH":   self._check_link_mismatch,
            "HTML_INLINE_STYLE_DENSITY": self._check_inline_style_density,
            "SENDING_HOUR_CHECK":        self._check_sending_hour,
            "EXTERNAL_IMAGE_COUNT":      self._check_external_images,
            "MISSING_MESSAGE_ID":        self._check_missing_message_id,
            # LING_001: must use a programmatic handler — the regex approach
            # compiled with re.IGNORECASE makes [A-Z] match lowercase too,
            # turning this into "any 5-letter word" which fires on everything.
            "EXCESSIVE_CAPS_CHECK":      self._check_excessive_caps,
        }

    # ── Main entry point ─────────────────────────────────────────────────────

    def evaluate(
        self,
        parsed_email,
        features=None,   # optional FeatureSet (unused here, kept for API compat)
        **kwargs,        # absorb any extra keyword arguments
    ) -> List[RuleMatch]:
        """
        Evaluate all enabled rules against the parsed email.

        Args:
            parsed_email: ParsedEmail produced by EmailParser.
            features:     FeatureSet (optional, not used here — rules work
                          directly on ParsedEmail for explainability).

        Returns:
            List of RuleMatch objects for every rule that fired.
        """
        rules = self._get_rules()
        handlers = self._get_handlers()
        matches: List[RuleMatch] = []

        for rule in rules:
            try:
                match = self._evaluate_rule(rule, parsed_email, handlers)
                if match:
                    matches.append(match)
            except Exception as exc:
                logger.warning(f"[RuleEngine] Rule {rule.rule_id} error: {exc}")

        logger.info(f"[RuleEngine] {len(matches)}/{len(rules)} rules fired.")
        return matches

    # ── Rule cache ───────────────────────────────────────────────────────────

    def _get_rules(self) -> List[_RuleProxy]:
        """
        Load enabled rules from DB, converted to session-detached _RuleProxy
        objects, with TTL-based in-memory caching.

        CRITICAL: We convert ORM Rule objects to _RuleProxy immediately after
        loading.  Storing raw ORM instances causes DetachedInstanceError on any
        subsequent request because Flask-SQLAlchemy expires the session when the
        request that loaded the rules ends — leaving the cached ORM objects
        disconnected from any database session.
        """
        now = time.time()
        if now - self._cache_ts < self._CACHE_TTL and self._rules_cache:
            return self._rules_cache
        try:
            from backend.models.database import Rule
            # .all() executes the query; we convert immediately while the
            # session is still open so all attributes are accessible.
            orm_rules = Rule.query.filter_by(is_enabled=True).all()
            RuleEngine._rules_cache = [
                _RuleProxy.from_orm(r) for r in orm_rules
            ]
            RuleEngine._cache_ts = now
            logger.debug(
                f"[RuleEngine] Loaded {len(self._rules_cache)} rules from DB."
            )
        except Exception as exc:
            logger.error(f"[RuleEngine] DB load error: {exc}")
        return self._rules_cache

    # ── Rule dispatcher ──────────────────────────────────────────────────────

    def _evaluate_rule(self, rule, pe, handlers) -> Optional[RuleMatch]:
        """Dispatch a rule to its handler (programmatic or regex)."""
        pattern = rule.pattern or ""
        if pattern in handlers:
            return handlers[pattern](rule, pe)
        return self._check_regex(rule, pe, pattern)

    # ── Regex evaluator ──────────────────────────────────────────────────────

    def _check_regex(
        self, rule, pe, pattern: str
    ) -> Optional[RuleMatch]:
        """
        Evaluate a regex pattern against the scan targets for this rule's
        category.  Returns a RuleMatch if the pattern fires on any target.

        KEY FIX vs v1: each category scans ONLY the relevant fields,
        so URL rules don't accidentally fire on CSS strings, and keyword
        rules scan decoded visible text, not raw HTML entities.
        """
        if not pattern:
            return None

        # Compile and cache the regex (avoids recompilation per request)
        if pattern not in self._compiled_regex:
            try:
                self._compiled_regex[pattern] = re.compile(
                    pattern, re.IGNORECASE | re.DOTALL | re.UNICODE
                )
            except re.error as exc:
                logger.warning(
                    f"[RuleEngine] Invalid regex {rule.rule_id}: {exc}"
                )
                return None

        regex = self._compiled_regex[pattern]

        for field_name, text in self._get_scan_targets(rule.category, pe):
            if not text:
                continue  # Skip empty fields — v1 false-positive root cause
            try:
                m = regex.search(text)
            except Exception:
                continue
            if m:
                return RuleMatch(
                    rule_id     = rule.rule_id,
                    rule_db_id  = rule.id,
                    name        = rule.name,
                    category    = rule.category,
                    weight      = rule.weight,
                    evidence    = self._evidence(m, text, field_name),
                    explanation = rule.description or rule.name,
                )
        return None

    def _get_scan_targets(
        self, category: str, pe
    ) -> List[Tuple[str, str]]:
        """
        Return (label, text) pairs appropriate for each rule category.

        KEY FIX: scoped targets per category.
        - URL rules scan actual URL strings, not CSS.
        - Keyword rules scan decoded visible text, not raw HTML entities.
        - Header rules scan raw header values only.
        This eliminates a major source of cross-category false positives.
        """
        # Build a clean all-body target once for fallback categories
        body_all = " ".join(filter(None, [
            pe.body_text      or "",
            pe.visible_text   or "",  # entity-decoded HTML text
            pe.subject        or "",
        ]))

        targets: Dict[str, List[Tuple[str, str]]] = {
            "url_analysis": [
                ("url_list",    " ".join(pe.urls) if pe.urls else ""),
                ("body_text",   pe.body_text  or ""),
                ("body_visible", pe.visible_text or ""),
            ],
            "content_keyword": [
                ("subject",     pe.subject    or ""),
                ("body_text",   pe.body_text  or ""),
                ("body_visible", pe.visible_text or ""),
            ],
            "sender_verification": [
                ("from_header",  pe.sender_raw   or ""),
                ("sender_email", pe.sender_email or ""),
            ],
            "header_authentication": [
                ("all_headers", str(pe.headers)),
                ("x_mailer",    pe.x_mailer or ""),
            ],
            "html_obfuscation": [
                ("html_raw",  pe.body_html  or ""),  # structural HTML patterns
                ("body_text", pe.body_text  or ""),
            ],
            "behavioral": [
                ("attachments", " ".join(pe.attachment_names)),
                ("body_all",    body_all),
            ],
            "linguistic_analysis": [
                ("body_text",   pe.body_text   or ""),
                ("body_visible", pe.visible_text or ""),
                ("subject",     pe.subject     or ""),
            ],
        }
        return targets.get(category, [("body_all", body_all)])

    @staticmethod
    def _evidence(
        m: re.Match, text: str, field: str, ctx: int = 60
    ) -> str:
        """Extract a readable snippet of context around a regex match."""
        start   = max(0, m.start() - ctx)
        end     = min(len(text), m.end() + ctx)
        snippet = text[start:end].strip()
        if start > 0:
            snippet = "…" + snippet
        if end < len(text):
            snippet += "…"
        return f"[{field}] {snippet[:200]}"

    # ── Programmatic rule handlers ────────────────────────────────────────────

    def _check_display_domain_mismatch(
        self, rule, pe
    ) -> Optional[RuleMatch]:
        """SND_001: Display name contains a brand but domain doesn't match."""
        brand_to_domain = {
            "paypal":    ["paypal.com"],
            "amazon":    ["amazon.com", "amazon.co.uk"],
            "google":    ["google.com", "googlemail.com"],
            "microsoft": ["microsoft.com", "outlook.com", "live.com"],
            "apple":     ["apple.com", "icloud.com"],
            "facebook":  ["facebook.com", "meta.com"],
            "crdb":      ["crdbbank.com", "crdb.co.tz"],
            "nmb":       ["nmbbank.co.tz"],
            "equity":    ["equitybank.co.tz"],
        }
        name   = (pe.sender_name   or "").lower()
        domain = (pe.sender_domain or "").lower()
        if not name or not domain:
            return None

        for brand, legit_domains in brand_to_domain.items():
            if brand in name:
                if not any(
                    domain == d or domain.endswith("." + d)
                    for d in legit_domains
                ):
                    return self._make_match(
                        rule,
                        f"Display name '{pe.sender_name}' claims '{brand}' "
                        f"but domain is '{domain}' "
                        f"(expected: {legit_domains[0]})",
                    )
        return None

    def _check_typosquatting(self, rule, pe) -> Optional[RuleMatch]:
        """SND_003: Sender domain is a lookalike of a known brand."""
        domain = (pe.sender_domain or "").lower()
        if not domain or len(domain) < 5:
            return None

        # Skip check for trusted domains — a subdomain of an institution
        # (e.g. cse.udsm.ac.tz) is not impersonating udsm.ac.tz
        if getattr(pe, "trusted_domain", False):
            return None

        for brand_domain in self.BRAND_DOMAINS:
            # Exact subdomain of the brand → legitimate, not a fake
            if domain == brand_domain or domain.endswith("." + brand_domain):
                return None

            ratio = difflib.SequenceMatcher(
                None, domain, brand_domain
            ).ratio()
            # Raise threshold from 0.75 → 0.80 to reduce false positives
            # from legitimately similar institutional domains
            if 0.80 < ratio < 1.0:
                return self._make_match(
                    rule,
                    f"'{domain}' looks like '{brand_domain}' "
                    f"(similarity: {ratio:.0%})",
                )
        return None

    def _check_reply_to_mismatch(
        self, rule, pe
    ) -> Optional[RuleMatch]:
        """SND_004: Reply-To domain differs from From domain."""
        if not pe.reply_to_domain or not pe.sender_domain:
            return None
        if pe.reply_to_domain != pe.sender_domain:
            return self._make_match(
                rule,
                f"From: @{pe.sender_domain} "
                f"but Reply-To: @{pe.reply_to_domain}",
            )
        return None

    def _check_dkim(self, rule, pe) -> Optional[RuleMatch]:
        """HDR_002: DKIM-Signature header absent."""
        if not pe.dkim_present:
            return self._make_match(rule, "DKIM-Signature header absent")
        return None

    def _check_dmarc(self, rule, pe) -> Optional[RuleMatch]:
        """HDR_003: DMARC=fail in Authentication-Results."""
        auth = pe.headers.get("authentication-results", "").lower()
        if "dmarc=fail" in auth:
            return self._make_match(
                rule, f"Authentication-Results: {auth[:120]}"
            )
        return None

    def _check_link_mismatch(self, rule, pe) -> Optional[RuleMatch]:
        """HTML_001: Visible text domain differs from href domain."""
        for pair in (pe.href_pairs or []):
            td = pair.get("text_domain", "")
            hd = pair.get("href_domain", "")
            if td and hd and td != hd:
                return self._make_match(
                    rule,
                    f"Displayed: '{pair.get('text', '')}' → "
                    f"Href domain: '{hd}'",
                )
        return None

    def _check_inline_style_density(
        self, rule, pe
    ) -> Optional[RuleMatch]:
        """HTML_004: Excessive inline CSS attributes."""
        count = getattr(pe, "inline_style_count", 0) or 0
        if count > 20:
            return self._make_match(
                rule,
                f"{count} inline style attributes (threshold: 20)",
            )
        return None

    def _check_sending_hour(self, rule, pe) -> Optional[RuleMatch]:
        """BEH_008: Email sent between midnight and 5 AM UTC."""
        if pe.date_header:
            try:
                import email.utils as eu
                dt = eu.parsedate_to_datetime(pe.date_header)
                if 0 <= dt.hour < 5:
                    return self._make_match(
                        rule,
                        f"Sent at {dt.strftime('%H:%M UTC')} (off-hours)",
                    )
            except Exception:
                pass
        # Fallback: use pre-computed send_hour_utc if available
        hour = getattr(pe, "send_hour_utc", None)
        if hour is not None and 0 <= hour < 5:
            return self._make_match(
                rule,
                f"Sent at hour {hour:02d}:xx UTC (off-hours)",
            )
        return None

    def _check_external_images(
        self, rule, pe
    ) -> Optional[RuleMatch]:
        """BEH_009: Images from 3+ external domains."""
        domains = list(getattr(pe, "external_image_domains", []) or [])
        n = len(set(domains))
        if n >= 3:
            return self._make_match(
                rule,
                f"Images from {n} external domains: "
                f"{', '.join(domains[:4])}",
            )
        return None

    def _check_missing_message_id(
        self, rule, pe
    ) -> Optional[RuleMatch]:
        """HDR_005: Message-ID header absent."""
        if not pe.has_message_id:
            return self._make_match(rule, "Message-ID header absent")
        return None

    def _check_excessive_caps(self, rule, pe) -> Optional[RuleMatch]:
        """
        LING_001: Detect 3+ genuinely ALL-CAPS words (5+ letters each).

        WHY PROGRAMMATIC (not regex):
        The rule engine compiles all patterns with re.IGNORECASE.
        A regex like r'\\b[A-Z]{5,}\\b' with IGNORECASE matches [a-zA-Z]{5,},
        meaning EVERY 5-letter word ("Customer", "prepared", "attached"...).
        This handler scans WITHOUT IGNORECASE so it correctly detects only
        truly uppercase words like URGENT, SUSPENDED, ACCOUNT, etc.
        """
        text = pe.body_text or pe.visible_text or ""
        if not text:
            return None
        # re.findall without re.IGNORECASE: only matches true ALL-CAPS words
        caps_words = re.findall(r"\b[A-Z]{5,}\b", text)
        if len(caps_words) >= 3:
            sample = " ".join(caps_words[:5])
            return self._make_match(
                rule,
                f"{len(caps_words)} ALL-CAPS words found: {sample}",
            )
        return None

    # ── Helper ───────────────────────────────────────────────────────────────

    def _make_match(self, rule, evidence: str) -> RuleMatch:
        """Build a RuleMatch from a programmatic check result."""
        return RuleMatch(
            rule_id     = rule.rule_id,
            rule_db_id  = rule.id,
            name        = rule.name,
            category    = rule.category,
            weight      = rule.weight,
            evidence    = evidence,
            explanation = rule.description or rule.name,
        )
