"""
PhishGuard v2 — Production-Grade Phishing Detection System
==========================================================
Entry point: Flask application factory.

Architecture:
  Raw Email → MIME Parser → Feature Extractor → Rule Engine
  → Correlation Engine → Legitimacy Engine → Risk Normalizer
  → Final Classifier → Explainability Engine → API Response

Author  : PhishGuard
Version : 2.0.0
"""

import logging
import sys
from pathlib import Path

from dotenv import load_dotenv   # Load .env before Config reads env vars
from flask import Flask, render_template
from flask_limiter import Limiter
from flask_limiter.util import get_remote_address
from flask_cors import CORS

from backend.api.routes import api_blueprint
from backend.models.database import init_db
from backend.utils.config import Config

# Load .env from the project root so DB credentials are available at startup
load_dotenv(Path(__file__).parent / ".env")


def create_app(config_class=Config) -> Flask:
    """
    Application factory — the ONLY place the app is instantiated.
    Using a factory enables proper testing isolation and multiple
    app instances with different configurations.
    """
   
    app = Flask(
        __name__,
        template_folder="frontend/templates",
        static_folder= "frontend/static",
    )
    app.config.from_object(config_class)

    # ── Bind SQLAlchemy to the app (must happen before any DB operations) ─
    from backend.models.database import db as _db
    _db.init_app(app)

    # ── Security: CORS restricted to same origin in production ──────────
    CORS(app, resources={r"/api/v1/*": {"origins": app.config.get("CORS_ORIGINS", "*")}})

    # ── Rate limiting: prevent brute-force and DoS ───────────────────────
    Limiter(
        get_remote_address,
        app=app,
        default_limits=["300 per day", "60 per minute"],
        storage_uri="memory://"
    )

    # ── Register all API routes under /api/v1 ────────────────────────────
    app.register_blueprint(api_blueprint, url_prefix="/api/v1")

    # ── Database initialisation (tables + rule sync) ─────────────────────
    with app.app_context():
        init_db()

    # ── Structured logging ────────────────────────────────────────────────
    log_level = getattr(logging, app.config.get("LOG_LEVEL", "INFO"))
    logging.basicConfig(
        level=log_level,
        format="%(asctime)s [%(levelname)-8s] %(name)s: %(message)s",
        handlers=[
            logging.StreamHandler(sys.stdout),
        ]
    )
    logging.getLogger("werkzeug").setLevel(logging.WARNING)

    # ── Frontend routes ───────────────────────────────────────────────────
    @app.route("/")
    def index():
        return render_template("index.html")

    @app.route("/dashboard")
    def dashboard():
        return render_template("dashboard.html")

    @app.route("/training")
    def training():
        return render_template("training.html")

    @app.route("/rules")
    def rules():
        return render_template("rules.html")

    # ── Health check endpoint ─────────────────────────────────────────────
    @app.route("/health")
    def health():
        from flask import jsonify
        return jsonify({"status": "ok", "version": "2.0.0"})

    app.logger.info("PhishGuard v2 initialised — http://127.0.0.1:5000/")
    return app


if __name__ == "__main__":
    application = create_app()
    application.run(
        host="127.0.0.1",
        port=5000,
        debug=True,
        use_reloader=True
    )
