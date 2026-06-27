"""
tests/test_system.py
======================
PhishGuard v2 system tests — validates every pipeline stage.
Runs with: pytest tests/ -v
Uses SQLite in-memory so no MySQL needed for testing.
"""
import pytest
from app import create_app
from backend.utils.config import TestingConfig
from backend.models.database import db as _db


@pytest.fixture(scope="session")
def app():
    app = create_app(TestingConfig)
    with app.app_context():
        _db.create_all()
        yield app

@pytest.fixture(scope="session")
def client(app):
    return app.test_client()


# ── Email Parser Tests ─────────────────────────────────────────────────────
class TestEmailParser:
    def test_parse_fields_extracts_sender_domain(self):
        from backend.engine.email_parser import EmailParser
        p = EmailParser()
        pe = p.parse_fields(sender="PayPal Security <support@crdb-verify.xyz>")
        assert pe.sender_domain == "crdb-verify.xyz"
        assert pe.sender_name   == "PayPal Security"

    def test_url_normalisation_lowercases_domain(self):
        # _normalise_url is exported at module level
        from backend.engine.email_parser import _normalise_url
        assert _normalise_url("HTTP://EVIL.COM/Path") == "http://evil.com/Path"

    def test_entropy_high_for_random_string(self):
        from backend.engine.email_parser import _shannon_entropy
        assert _shannon_entropy("abcdefghijklmnop") > 3.5

    def test_entropy_low_for_repeated_chars(self):
        from backend.engine.email_parser import _shannon_entropy
        assert _shannon_entropy("aaaaaaaaaaaaaaa") < 1.0

    def test_html_extracts_visible_text(self):
        from backend.engine.email_parser import EmailParser
        p = EmailParser()
        pe = p.parse_fields(body_html="<html><body><p>Hello World</p></body></html>")
        # visible_text (was body_visible in old API)
        assert "Hello World" in (pe.visible_text or "")

    def test_html_finds_form(self):
        from backend.engine.email_parser import EmailParser
        p = EmailParser()
        pe = p.parse_fields(body_html='<form action="http://evil.com/steal"></form>')
        assert pe.has_form
        assert "http://evil.com/steal" in pe.form_actions


# ── Feature Engine Tests ────────────────────────────────────────────────────
class TestFeatureExtractor:
    """
    These tests use FeatureEngine (canonical) not the legacy FeatureExtractor.
    Attribute names match feature_engine.FeatureSet, not the old feature_extractor.FeatureSet.
    """
    def setup_method(self):
        from backend.engine.email_parser  import EmailParser
        from backend.engine.feature_engine import FeatureEngine
        self.parser    = EmailParser()
        self.extractor = FeatureEngine()

    def test_detects_ip_url(self):
        pe = self.parser.parse_fields(body_text="Click: http://192.168.1.1/login")
        fs = self.extractor.extract(pe)
        # ParsedEmail already computes has_ip_url; FeatureEngine copies it
        assert fs.has_ip_url

    def test_detects_link_mismatch(self):
        pe = self.parser.parse_fields(
            body_html='<a href="http://evil.com">www.paypal.com</a>')
        fs = self.extractor.extract(pe)
        # link_text_mismatch_count > 0 is the correct attribute name
        assert fs.link_text_mismatch_count > 0

    def test_free_email_detection(self):
        pe = self.parser.parse_fields(sender="Bank <support@gmail.com>")
        fs = self.extractor.extract(pe)
        # sender_uses_free_email is the correct attribute name
        assert fs.sender_uses_free_email

    def test_urgency_detection(self):
        pe = self.parser.parse_fields(
            body_text="Your account is suspended. Verify now!")
        fs = self.extractor.extract(pe)
        # has_urgency_language is the correct attribute name
        assert fs.has_urgency_language


# ── Scoring Engine Tests ───────────────────────────────────────────────────
class TestScoringEngine:
    def setup_method(self):
        from backend.engine.scoring_engine     import ScoringEngine
        from backend.engine.correlation_engine import CorrelationResult
        from backend.engine.legitimacy_engine  import LegitimacyResult
        self.scorer   = ScoringEngine()
        self.empty_cr = CorrelationResult()
        self.empty_lr = LegitimacyResult()

    def test_no_matches_returns_zero(self):
        result = self.scorer.score([], self.empty_cr, self.empty_lr)
        assert result.risk_score    == 0.0
        assert result.classification == "legitimate"

    def test_high_weight_matches_score_phishing(self):
        from backend.engine.rule_engine import RuleMatch
        matches = [
            RuleMatch("URL_001", 1, "IP URL",       "url_analysis",       3.0, "test", "test"),
            RuleMatch("KW_002",  2, "Credentials",  "content_keyword",    2.5, "test", "test"),
            RuleMatch("SND_003", 3, "Typosquatting","sender_verification", 3.0, "test", "test"),
        ]
        result = self.scorer.score(matches, self.empty_cr, self.empty_lr)
        assert result.risk_score    >= 55
        assert result.classification == "phishing"

    def test_legitimacy_deduction_reduces_score(self):
        from backend.engine.rule_engine    import RuleMatch
        from backend.engine.legitimacy_engine import LegitimacyResult
        matches = [RuleMatch("KW_001", 1, "Urgency", "content_keyword", 1.0, "test", "test")]
        legit   = LegitimacyResult(
            legitimacy_deduction=15.0,
            deduction_reasons=[{"signal": "DKIM", "deduction": 8.0, "explanation": ""}],
        )
        result   = self.scorer.score(matches, self.empty_cr, legit)
        baseline = self.scorer.score(matches, self.empty_cr, self.empty_lr)
        assert result.risk_score < baseline.risk_score

    def test_sigmoid_normalisation_is_monotone(self):
        scores = [self.scorer._normalise(r) for r in [0, 2, 5, 8, 12, 16, 22, 30]]
        assert scores == sorted(scores)


# ── Correlation Engine Tests ───────────────────────────────────────────────
class TestCorrelationEngine:
    def setup_method(self):
        from backend.engine.email_parser      import EmailParser
        from backend.engine.feature_engine    import FeatureEngine  # canonical engine
        from backend.engine.correlation_engine import CorrelationEngine
        self.parser    = EmailParser()
        self.extractor = FeatureEngine()
        self.engine    = CorrelationEngine()

    def test_classic_phish_combo_fires(self):
        from backend.engine.feature_engine import FeatureSet
        # Build a FeatureSet that satisfies the Credential Phishing composite
        fs = FeatureSet(
            has_ip_url            = True,   # suspicious URL
            has_credential_request= True,   # asks for credentials
            has_urgency_language  = True,   # urgency pressure
        )
        result = self.engine.correlate(fs, [])
        names = [c["name"] for c in result.triggered_composites]
        assert "Credential Phishing" in names
        assert result.composite_bonus >= 15.0

    def test_no_signals_gives_zero_bonus(self):
        from backend.engine.feature_engine import FeatureSet
        fs = FeatureSet()
        result = self.engine.correlate(fs, [])
        assert result.composite_bonus == 0.0


# ── Legitimacy Engine Tests ────────────────────────────────────────────────
class TestLegitimacyEngine:
    def setup_method(self):
        from backend.engine.feature_engine    import FeatureSet
        from backend.engine.legitimacy_engine  import LegitimacyEngine
        self.engine  = LegitimacyEngine()
        self.FeatureSet = FeatureSet
        self.fs      = FeatureSet()

    def test_dkim_and_spf_pass_gives_deduction(self):
        # dkim_pass and spf_pass are the correct attribute names in FeatureSet
        fs = self.FeatureSet(dkim_pass=True, spf_pass=True)
        result = self.engine.evaluate(fs)
        assert result.legitimacy_deduction >= 13.0  # 8 (DKIM) + 5 (SPF) minimum

    def test_no_legitimacy_signals_gives_zero(self):
        # A FeatureSet with no legitimacy signals except the clean-content deduction.
        # Set missing_message_id=True (no Message-ID → no "Proper Message-ID" deduction).
        # Set has_urgency_language=True to DISQUALIFY the clean-content deduction,
        # so we truly get zero deductions. This verifies that non-clean emails
        # don't accidentally receive the clean-content deduction.
        fs = self.FeatureSet(
            missing_message_id  = True,   # no proper message-id deduction
            has_urgency_language = True,   # disqualifies the clean-content deduction
        )
        result = self.engine.evaluate(fs)
        assert result.legitimacy_deduction == 0.0

    def test_deduction_capped_at_25(self):
        # Fill every legitimacy signal to test the cap
        fs = self.FeatureSet(
            dkim_pass                    = True,
            spf_pass                     = True,
            recipient_personally_addressed = True,
            missing_message_id           = False,
            malformed_message_id         = False,
            has_unsubscribe_header       = True,
            url_count                    = 3,
            link_text_mismatch_count     = 0,
            has_ip_url                   = False,
            has_shortener                = False,
            has_suspicious_tld           = False,
            has_at_in_url                = False,
        )
        result = self.engine.evaluate(fs)
        # Cap was raised to 30.0 to accommodate the clean-content deduction
        assert result.legitimacy_deduction <= 30.0


# ── Full API Integration Tests ─────────────────────────────────────────────
class TestAPI:
    def test_health_check(self, client):
        res = client.get("/health")
        assert res.status_code == 200
        assert res.json["status"] == "ok"

    def test_analyse_empty_body_returns_error(self, client):
        import json
        res = client.post("/api/v1/analyse",
            data=json.dumps({}), content_type="application/json")
        data = res.get_json()
        assert data["success"] is False

    def test_clear_phishing_email_scores_high(self, client):
        import json
        payload = {
            "sender":    "CRDB Bank <security@crdb-verify.xyz>",
            "subject":   "URGENT: Your account is suspended",
            "body_text": (
                "Dear Customer, your CRDB account is suspended. "
                "Verify your PIN immediately: http://192.168.1.1/verify "
                "Enter your PIN and password or your account will be closed."
            ),
            "language": "en",
        }
        res  = client.post("/api/v1/analyse",
            data=json.dumps(payload), content_type="application/json")
        data = res.get_json()
        assert res.status_code == 200
        assert data["success"] is True
        assert data["risk_score"] >= 55, f"Expected phishing, got {data['risk_score']}"
        assert data["classification"] == "phishing"

    def test_legitimate_university_email_scores_low(self, client):
        import json
        payload = {
            "sender":    "registrar@udsm.ac.tz",
            "subject":   "Course Registration Confirmation — Semester 1 2024/2025",
            "body_text": (
                "Dear John Msangi,\n\n"
                "Your course registration for Semester 1 has been confirmed.\n"
                "CS 401 — Software Engineering (3 Credits)\n"
                "CS 405 — Database Systems (3 Credits)\n\n"
                "Visit: https://portal.udsm.ac.tz for details.\n\n"
                "University of Dar es Salaam\nRegistrar's Office"
            ),
            "headers": "DKIM-Signature: v=1; a=rsa-sha256; d=udsm.ac.tz\nReceived-SPF: pass",
            "language": "en",
        }
        res  = client.post("/api/v1/analyse",
            data=json.dumps(payload), content_type="application/json")
        data = res.get_json()
        assert res.status_code == 200
        # Must NOT be phishing (false positive check)
        assert data["classification"] != "phishing", \
            f"False positive! UDSM email scored {data['risk_score']} = {data['classification']}"

    def test_rules_endpoint_returns_list(self, client):
        res = client.get("/api/v1/rules")
        data = res.get_json()
        assert res.status_code == 200
        assert len(data["rules"]) >= 20

    def test_training_endpoint_returns_samples(self, client):
        res = client.get("/api/v1/training")
        data = res.get_json()
        assert res.status_code == 200
        assert data["total"] >= 8
