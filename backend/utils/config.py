"""
backend/utils/config.py
=======================
Central configuration for PhishGuard v2.
All sensitive values read from environment variables with
safe offline defaults so the system works in university labs.
"""
import os
from pathlib import Path

BASE_DIR = Path(__file__).resolve().parent.parent.parent


class Config:
    # ── Flask ────────────────────────────────────────────────
    SECRET_KEY: str   = os.getenv("SECRET_KEY", "phishguard-v2-secure-key-2024-tz")
    DEBUG: bool       = os.getenv("DEBUG", "True") == "True"
    LOG_LEVEL: str    = os.getenv("LOG_LEVEL", "INFO")
    CORS_ORIGINS: str = os.getenv("CORS_ORIGINS", "*")

    # ── MySQL ─────────────────────────────────────────────────
    DB_HOST: str     = os.getenv("DB_HOST",     "localhost")
    DB_PORT: int     = int(os.getenv("DB_PORT", "3306"))
    DB_USER: str     = os.getenv("DB_USER",     "root")
    DB_PASSWORD: str = os.getenv("DB_PASSWORD", "")
    DB_NAME: str     = os.getenv("DB_NAME",     "phishguard")
    SQLALCHEMY_DATABASE_URI: str = (
        f"mysql+pymysql://{os.getenv('DB_USER','root')}:"
        f"{os.getenv('DB_PASSWORD','')}@"
        f"{os.getenv('DB_HOST','localhost')}:"
        f"{os.getenv('DB_PORT','3306')}/"
        f"{os.getenv('DB_NAME','phishguard')}?charset=utf8mb4"
    )
    SQLALCHEMY_TRACK_MODIFICATIONS: bool = False
    SQLALCHEMY_POOL_RECYCLE: int = 280   # Recycle before MySQL 5-min timeout
    # pool_pre_ping: test each connection before use so stale/dead connections
    # (e.g. after MySQL restarts) are transparently replaced without a 500 error
    SQLALCHEMY_ENGINE_OPTIONS: dict = {"pool_pre_ping": True}

    # ── Analysis ─────────────────────────────────────────────
    MAX_EMAIL_SIZE_KB: int         = 500
    ANALYSIS_TIMEOUT_SECONDS: int  = 15

    # ── PDF ───────────────────────────────────────────────────
    PDF_OUTPUT_DIR: Path = BASE_DIR / "exports"
    PDF_OUTPUT_DIR.mkdir(exist_ok=True)

    # ── i18n ──────────────────────────────────────────────────
    SUPPORTED_LANGUAGES: list = ["en", "sw"]
    DEFAULT_LANGUAGE: str     = "en"

    # ── Logging ───────────────────────────────────────────────
    LOG_FILE: Path = BASE_DIR / "logs" / "phishguard.log"
    LOG_FILE.parent.mkdir(exist_ok=True)


class TestingConfig(Config):
    TESTING: bool                = True
    SQLALCHEMY_DATABASE_URI: str = "sqlite:///:memory:"
    RATELIMIT_ENABLED: bool      = False
    WTF_CSRF_ENABLED: bool       = False
