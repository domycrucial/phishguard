"""
tests/test_rule_engine.py
Unit tests for the Email Parser, Rule Engine, and Scoring Engine.
These tests run without Flask context / DB connection.
"""
import pytest
from backend.engine.email_parser   import EmailParser, ParsedEmail
from backend.engine.scoring_engine import ScoringEngine
from backend.engine.rule_engine    import RuleMatch


# ── Email Parser Tests ────────────────────────────────────────
class TestEmailParser:
    def setup_method(self):
        self.parser = EmailParser()

    def test_parse_fields_extracts_sender_domain(self):
        parsed = self.parser.parse_fields(
            sender="PayPal Security <support@paypal-verify.xyz>",
            subject="Test",
            body_text="Hello"
        )
        assert parsed.sender_domain == "paypal-verify.xyz"
        assert parsed.sender_name   == "PayPal Security"

    def test_parse_fields_extracts_urls(self):
        parsed = self.parser.parse_fields(
            body_text="Visit http://example.com and https://test.org/path"
        )
        assert "http://example.com" in parsed.urls
        assert "https://test.org/path" in parsed.urls

    def test_parse_raw_extracts_subject(self):
        raw = "From: test@example.com\r\nSubject: Hello World\r\n\r\nBody here."
        parsed = self.parser.parse_raw(raw)
        assert parsed.subject == "Hello World"

    def test_parse_raw_detects_dkim_presence(self):
        raw = (
            "From: test@example.com\r\n"
            "DKIM-Signature: v=1; a=rsa-sha256; d=example.com\r\n"
            "\r\nBody."
        )
        parsed = self.parser.parse_raw(raw)
        assert parsed.dkim_present is True

    def test_parse_fields_handles_empty_input(self):
        """Parser should never crash on empty input."""
        parsed = self.parser.parse_fields()
        assert isinstance(parsed, ParsedEmail)
        assert parsed.urls == []

    def test_html_analysis_extracts_href_pairs(self):
        html = '<a href="http://evil.com">www.paypal.com</a>'
        parsed = self.parser.parse_fields(body_html=html)
        assert len(parsed.href_pairs) == 1
        assert parsed.href_pairs[0]["href"] == "http://evil.com"

    def test_html_analysis_detects_form(self):
        html = '<form action="http://evil.com/steal"><input type="password"/></form>'
        parsed = self.parser.parse_fields(body_html=html)
        assert parsed.has_form is True
        assert "http://evil.com/steal" in parsed.form_actions


# ── Scoring Engine Tests ──────────────────────────────────────
class TestScoringEngine:
    def setup_method(self):
        self.engine = ScoringEngine()

    def _make_match(self, rule_id, category, weight) -> RuleMatch:
        return RuleMatch(
            rule_id=rule_id,
            rule_db_id=1,
            name=f"Test rule {rule_id}",
            category=category,
            weight=weight,
            evidence="test evidence",
            explanation="test explanation",
        )

    def test_no_matches_returns_legitimate(self):
        result = self.engine.score([])
        assert result.classification == "legitimate"
        assert result.risk_score     == 0.0
        assert result.confidence     >= 0.8

    def test_high_weight_matches_return_phishing(self):
        matches = [
            self._make_match("URL_001", "url_analysis",          3.0),
            self._make_match("SND_003", "sender_verification",   3.0),
            self._make_match("HDR_001", "header_authentication", 3.0),
            self._make_match("KW_002",  "content_keyword",       2.5),
        ]
        result = self.engine.score(matches)
        assert result.classification == "phishing"
        assert result.risk_score     >= 60

    def test_low_weight_match_returns_legitimate_or_suspicious(self):
        matches = [self._make_match("KW_006", "content_keyword", 1.0)]
        result = self.engine.score(matches)
        assert result.classification in ("legitimate", "suspicious")

    def test_score_never_exceeds_100(self):
        # Flood with max-weight matches
        matches = [
            self._make_match(f"RULE_{i:03d}", "url_analysis", 3.0)
            for i in range(30)
        ]
        result = self.engine.score(matches)
        assert result.risk_score <= 100.0

    def test_score_contribution_populated(self):
        matches = [self._make_match("URL_001", "url_analysis", 2.0)]
        result = self.engine.score(matches)
        assert result.rule_matches[0].score_contribution > 0

    def test_category_scores_populated(self):
        matches = [
            self._make_match("URL_001", "url_analysis",  2.0),
            self._make_match("KW_001",  "content_keyword", 1.5),
        ]
        result = self.engine.score(matches)
        assert "url_analysis"    in result.category_scores
        assert "content_keyword" in result.category_scores

    def test_confidence_within_bounds(self):
        matches = [self._make_match("URL_001", "url_analysis", 2.0)]
        result = self.engine.score(matches)
        assert 0.0 <= result.confidence <= 1.0


# ── Sanitiser Tests ───────────────────────────────────────────
class TestSanitiser:
    def test_strips_script_tags(self):
        from backend.utils.sanitiser import sanitise_input
        result = sanitise_input('<script>alert("xss")</script>hello')
        assert "<script>" not in result
        assert "hello" in result

    def test_blocks_javascript_protocol(self):
        from backend.utils.sanitiser import sanitise_input
        result = sanitise_input('javascript:alert(1)')
        assert "javascript:" not in result

    def test_enforces_max_length(self):
        from backend.utils.sanitiser import sanitise_input
        result = sanitise_input("a" * 1000, max_length=100)
        assert len(result) == 100

    def test_empty_string_returns_empty(self):
        from backend.utils.sanitiser import sanitise_input
        assert sanitise_input("") == ""

    def test_validate_rule_rejects_invalid_category(self):
        from backend.utils.sanitiser import validate_rule_input
        errors = validate_rule_input({
            "name": "Test", "category": "invalid_cat",
            "weight": 1.0, "pattern": r"\btest\b"
        })
        assert any("category" in e.lower() for e in errors)

    def test_validate_rule_rejects_bad_regex(self):
        from backend.utils.sanitiser import validate_rule_input
        errors = validate_rule_input({
            "name": "Test", "category": "content_keyword",
            "weight": 1.0, "pattern": "[unclosed("
        })
        assert any("regex" in e.lower() or "pattern" in e.lower() for e in errors)

    def test_validate_rule_passes_valid_input(self):
        from backend.utils.sanitiser import validate_rule_input
        errors = validate_rule_input({
            "name":     "Valid rule",
            "category": "content_keyword",
            "weight":   1.5,
            "pattern":  r"\b(urgent|verify)\b",
        })
        assert errors == []
