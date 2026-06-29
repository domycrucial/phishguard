"""
tests/test_api.py
Basic smoke tests for the PhishGuard Flask API.
Uses SQLite in-memory DB (TestingConfig) — no MySQL required.
Run with:  pytest tests/ -v
"""
import json
import pytest
from app import create_app
from backend.utils.config import TestingConfig
from backend.models.database import db as _db, Email


# ── Fixtures ──────────────────────────────────────────────────
@pytest.fixture(scope="session")
def app():
    """Create app with testing config."""
    application = create_app(TestingConfig)
    with application.app_context():
        _db.create_all()
        yield application


@pytest.fixture(scope="session")
def client(app):
    return app.test_client()


# ── Tests ──────────────────────────────────────────────────────
class TestAnalyseEndpoint:
    def test_missing_body_returns_400(self, client):
        res = client.post("/api/v1/analyse",
                          data="not-json",
                          content_type="application/json")
        assert res.status_code == 400

    def test_empty_payload_returns_error(self, client):
        res = client.post("/api/v1/analyse",
                          data=json.dumps({}),
                          content_type="application/json")
        data = res.get_json()
        assert data["success"] is False

    def test_phishing_email_returns_high_score(self, client):
        payload = {
            "sender":    "security@paypal-verify.xyz",
            "subject":   "URGENT: Your account has been suspended",
            "body_text": (
                "Dear Customer, your account is suspended. "
                "Verify now: http://192.168.1.1/verify "
                "Enter your PIN and password immediately."
            ),
            "language": "en",
        }
        res  = client.post("/api/v1/analyse",
                           data=json.dumps(payload),
                           content_type="application/json")
        data = res.get_json()
        assert res.status_code == 200
        assert data["success"] is True
        assert data["risk_score"] >= 30, "Expected at least suspicious score"

    def test_legitimate_email_returns_low_score(self, client):
        payload = {
            "sender":    "registrar@udsm.ac.tz",
            "subject":   "Course Registration Confirmation",
            "body_text": (
                "Dear John Msangi, your course registration for Semester 1 "
                "has been confirmed. Visit https://portal.udsm.ac.tz for details."
            ),
            "language": "en",
        }
        res  = client.post("/api/v1/analyse",
                           data=json.dumps(payload),
                           content_type="application/json")
        data = res.get_json()
        assert res.status_code == 200
        assert data["success"] is True
        # Legitimate email should score lower than a clear phishing attempt
        assert data["risk_score"] < 80

    def test_swahili_language_returns_sw_narrative(self, client):
        payload = {
            "sender":    "noreply@test.com",
            "subject":   "Test",
            "body_text": "Hello, click this link to win a prize!",
            "language":  "sw",
        }
        res  = client.post("/api/v1/analyse",
                           data=json.dumps(payload),
                           content_type="application/json")
        data = res.get_json()
        assert res.status_code == 200
        assert data["success"] is True
        assert data["explanation"]["language"] == "sw"


class TestHistoryEndpoint:
    def test_returns_paginated_results(self, client):
        res  = client.get("/api/v1/history?page=1&per_page=5")
        data = res.get_json()
        assert res.status_code == 200
        assert "items" in data
        assert "total" in data

    def test_filter_by_classification(self, client):
        res  = client.get("/api/v1/history?classification=phishing")
        data = res.get_json()
        assert res.status_code == 200
        # All returned items should have classification=phishing
        for item in data.get("items", []):
            assert item["classification"] == "phishing"


class TestStatsEndpoint:
    def test_stats_returns_expected_keys(self, client):
        res  = client.get("/api/v1/stats")
        data = res.get_json()
        assert res.status_code == 200
        for key in ["total", "phishing", "legitimate", "trend"]:
            assert key in data


class TestRulesEndpoint:
    def test_get_rules_returns_list(self, client):
        res  = client.get("/api/v1/rules")
        data = res.get_json()
        assert res.status_code == 200
        assert "rules" in data
        # Should have seeded rules from rules_definitions.py
        assert len(data["rules"]) > 0

    def test_create_custom_rule(self, client):
        payload = {
            "name":        "Test custom rule",
            "category":    "content_keyword",
            "weight":      1.5,
            "pattern":     r"\btest_phish\b",
            "description": "Detects test_phish keyword",
        }
        res  = client.post("/api/v1/rules",
                           data=json.dumps(payload),
                           content_type="application/json")
        data = res.get_json()
        assert res.status_code == 201
        assert data["success"] is True
        assert "CUSTOM_" in data["rule_id"]

    def test_create_rule_invalid_regex_returns_error(self, client):
        payload = {
            "name":     "Bad regex rule",
            "category": "content_keyword",
            "weight":   1.0,
            "pattern":  "[invalid regex(",   # Deliberately invalid
        }
        res  = client.post("/api/v1/rules",
                           data=json.dumps(payload),
                           content_type="application/json")
        data = res.get_json()
        assert data["success"] is False


class TestTrainingEndpoint:
    def test_returns_all_samples(self, client):
        res  = client.get("/api/v1/training")
        data = res.get_json()
        assert res.status_code == 200
        assert data["total"] >= 8   # We seeded 8 training samples

    def test_filter_by_type(self, client):
        res  = client.get("/api/v1/training?type=phishing")
        data = res.get_json()
        assert res.status_code == 200
        for sample in data["samples"]:
            assert sample["expected_type"] == "phishing"


class TestRemediationEndpoint:
    def test_remediate_quarantine(self, client, app):
        with app.app_context():
            from backend.models.database import AnalysisResult
            email = Email(
                sender="test@bad-sender.com",
                recipient="user@internal.com",
                subject="Test Quarantine",
                body_text="Hello, visit http://malicious-site.com",
                status="active"
            )
            _db.session.add(email)
            _db.session.flush()
            analysis = AnalysisResult(
                email_id=email.id,
                risk_score=90.0,
                classification="phishing",
                confidence=0.9
            )
            _db.session.add(analysis)
            _db.session.commit()
            email_id = email.id
            analysis_id = analysis.id

        # Call quarantine action
        payload = {"analysis_id": analysis_id, "action": "quarantine"}
        res = client.post("/api/v1/remediate",
                          data=json.dumps(payload),
                          content_type="application/json")
        data = res.get_json()
        assert res.status_code == 200
        assert data["success"] is True

        # Verify change in db
        with app.app_context():
            updated_email = _db.session.get(Email, email_id)
            assert updated_email.status == "quarantined"

            # Check remediation logs
            from backend.models.database import RemediationAction
            log = RemediationAction.query.filter_by(email_id=email_id, action_type="quarantine").first()
            assert log is not None
            assert log.status == "success"

    def test_remediate_block_sender_and_fast_path(self, client, app):
        with app.app_context():
            from backend.models.database import AnalysisResult
            email = Email(
                sender="spammer@scammy-domain.com",
                recipient="user@internal.com",
                subject="Scam offer",
                body_text="Give me money",
                status="active"
            )
            _db.session.add(email)
            _db.session.flush()
            analysis = AnalysisResult(
                email_id=email.id,
                risk_score=90.0,
                classification="phishing",
                confidence=0.9
            )
            _db.session.add(analysis)
            _db.session.commit()
            email_id = email.id
            analysis_id = analysis.id

        # Call block_sender action
        payload = {"analysis_id": analysis_id, "action": "block_sender"}
        res = client.post("/api/v1/remediate",
                          data=json.dumps(payload),
                          content_type="application/json")
        data = res.get_json()
        assert res.status_code == 200
        assert data["success"] is True

        # Verify indicator added to BlockedIndicator
        with app.app_context():
            from backend.models.database import BlockedIndicator
            ind = BlockedIndicator.query.filter_by(value="spammer@scammy-domain.com").first()
            assert ind is not None
            assert ind.indicator_type == "sender"

        # Now, submit a new email from this sender via /api/v1/analyse
        # It should trigger the fast-path check and return 100/100 risk score
        analyse_payload = {
            "sender": "spammer@scammy-domain.com",
            "subject": "Hello again",
            "body_text": "Need money urgently",
            "language": "en"
        }
        res_analyse = client.post("/api/v1/analyse",
                                  data=json.dumps(analyse_payload),
                                  content_type="application/json")
        data_analyse = res_analyse.get_json()
        assert res_analyse.status_code == 200
        assert data_analyse["success"] is True
        assert data_analyse["risk_score"] == 100.0
        assert data_analyse["classification"] == "phishing"
        assert data_analyse["rules_triggered"] == 1
        assert "spammer@scammy-domain.com" in data_analyse["triggered_rules"][0]["evidence"]

    def test_remediate_block_urls(self, client, app):
        with app.app_context():
            from backend.models.database import AnalysisResult
            email = Email(
                sender="info@news.com",
                recipient="user@internal.com",
                subject="Check this",
                body_text="Click here: http://phish-link.tk/verify",
                status="active"
            )
            _db.session.add(email)
            _db.session.flush()
            analysis = AnalysisResult(
                email_id=email.id,
                risk_score=90.0,
                classification="phishing",
                confidence=0.9
            )
            _db.session.add(analysis)
            _db.session.commit()
            email_id = email.id
            analysis_id = analysis.id

        # Call block_urls action
        payload = {"analysis_id": analysis_id, "action": "block_urls"}
        res = client.post("/api/v1/remediate",
                          data=json.dumps(payload),
                          content_type="application/json")
        data = res.get_json()
        assert res.status_code == 200
        assert data["success"] is True

        # Verify domain added to BlockedIndicator
        with app.app_context():
            from backend.models.database import BlockedIndicator
            ind = BlockedIndicator.query.filter_by(value="phish-link.tk").first()
            assert ind is not None
            assert ind.indicator_type == "domain"


class TestTrustedDomainsEndpoint:
    def test_add_list_delete_trusted_domain(self, client):
        # 1. List trusted domains
        res = client.get("/api/v1/trusted-domains")
        assert res.status_code == 200
        data = res.get_json()
        assert data["success"] is True
        assert isinstance(data["domains"], list)

        # 2. Add a trusted domain
        payload = {"domain": "test-domain-added.com"}
        res = client.post("/api/v1/trusted-domains",
                           data=json.dumps(payload),
                           content_type="application/json")
        assert res.status_code == 201
        data = res.get_json()
        assert data["success"] is True
        assert data["domain"]["domain"] == "test-domain-added.com"
        domain_id = data["domain"]["id"]

        # 3. Add duplicate should fail
        res = client.post("/api/v1/trusted-domains",
                           data=json.dumps(payload),
                           content_type="application/json")
        assert res.status_code == 400

        # 4. Delete the trusted domain
        res = client.delete(f"/api/v1/trusted-domains/{domain_id}")
        assert res.status_code == 200
        data = res.get_json()
        assert data["success"] is True

        # 5. Delete non-existent should return 404
        res = client.delete(f"/api/v1/trusted-domains/{domain_id}")
        assert res.status_code == 404



