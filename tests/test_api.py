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
from backend.models.database import db as _db


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
