# PhishGuard v2 — Phishing Email Detection System

> A fully offline-capable, modular, and explainable phishing email detection system
> built with Flask and Python. Designed for deployment in Tanzanian university labs
> and any environment where accurate, low-false-positive detection is required.

---

## Table of Contents

1. [Overview](#1-overview)
2. [System Architecture](#2-system-architecture)
3. [Project Structure](#3-project-structure)
4. [Quick Start](#4-quick-start)
5. [Configuration](#5-configuration)
6. [Engine Files Explained](#6-engine-files-explained)
7. [Pipeline Flow](#7-pipeline-flow)
8. [Scoring Model](#8-scoring-model)
9. [API Reference](#9-api-reference)
10. [Database Schema](#10-database-schema)
11. [Detection Rules](#11-detection-rules)
12. [Frontend Pages](#12-frontend-pages)
13. [Testing](#13-testing)
14. [Troubleshooting](#14-troubleshooting)

---

## 1. Overview

PhishGuard is a web application that analyses email content to detect phishing
attempts. It accepts an email (either as a raw RFC-2822 string or as individual
fields — sender, subject, body) and returns a risk score from 0 to 100, a
classification (legitimate / suspicious / phishing), and a full human-readable
explanation of why the classification was made.

**Key design goals:**
- **Low false positives** — legitimate emails from Gmail, Yahoo, universities,
  and small businesses must score as legitimate even without authentication headers.
- **Explainability** — every decision is backed by specific evidence the analyst can read.
- **Offline-capable** — runs entirely on localhost with no external API calls.
- **Tanzanian context** — includes local bank domains (CRDB, NMB), universities
  (UDSM, UDOM), and Swahili language explanations.

---

## 2. System Architecture

```
Browser (HTML/JS)
      |
      | HTTP
      v
Flask App  (app.py)
      |
      | Blueprint
      v
API Routes  (backend/api/routes.py)
      |
      v
Analysis Pipeline  (backend/engine/analysis_pipeline.py)
      |
      |-- [1] EmailParser         →  ParsedEmail dataclass
      |-- [2] Normalizer          →  clean whitespace / encoding
      |-- [3] FeatureEngine       →  FeatureSet  (50+ signals)
      |-- [4] RuleEngine          →  List[RuleMatch]  (DB rules)
      |-- [5] CorrelationEngine   →  CorrelationResult  (composite patterns)
      |-- [6] LegitimacyEngine    →  LegitimacyResult  (negative scoring)
      |-- [7] ScoringEngine       →  ScoringResult  (0-100 risk score)
      |-- [8] ExplainabilityEngine→  human-readable narrative (EN / SW)
      |-- [9] DB Persist          →  MySQL via SQLAlchemy
      |
      v
JSON response  →  Browser renders result
```

**Core principle:** The system uses a two-directional scoring model:
- Phishing signals **add** score (rules, composite patterns).
- Legitimacy signals **subtract** score (DKIM/SPF pass, personalised greeting,
  clean URL structure, no phishing keywords).

This prevents false positives on legitimate emails that happen to contain
incidental suspicious-looking content.

---

## 3. Project Structure

```
phishing_detector/
│
├── app.py                         # Flask application factory (entry point)
├── requirements.txt               # Python package dependencies
├── setup.cfg                      # Pytest configuration
├── start.bat                      # Windows one-click start script
├── start.sh                       # Linux/macOS one-click start script
├── .env                           # Your local configuration (not in git)
├── .env.example                   # Template for .env
├── .gitignore                     # Files excluded from git
│
├── backend/                       # All server-side logic
│   ├── __init__.py
│   ├── exceptions.py              # Custom exception classes for the pipeline
│   │
│   ├── api/
│   │   ├── __init__.py
│   │   └── routes.py              # REST API endpoints (all /api/* routes)
│   │
│   ├── engine/                    # The detection engine (core logic)
│   │   ├── __init__.py
│   │   ├── analysis_pipeline.py   # Orchestrates all 9 pipeline stages
│   │   ├── email_parser.py        # MIME parser → ParsedEmail dataclass
│   │   ├── feature_engine.py      # ParsedEmail → FeatureSet (50+ features)
│   │   ├── rule_engine.py         # DB rules → List[RuleMatch] (with cache)
│   │   ├── rules_definitions.py   # ALL_RULES: the built-in rule catalogue
│   │   ├── correlation_engine.py  # Detects combined phishing patterns
│   │   ├── legitimacy_engine.py   # Computes score deductions for legit signals
│   │   ├── scoring_engine.py      # Produces final 0-100 risk score
│   │   ├── explainability_engine.py # Generates human-readable explanations
│   │   └── feature_extractor.py  # Legacy file — not used; superseded by feature_engine.py
│   │
│   ├── models/
│   │   ├── __init__.py
│   │   └── database.py            # SQLAlchemy ORM models + init_db() + rule sync
│   │
│   └── utils/
│       ├── __init__.py
│       ├── config.py              # Config class (reads .env variables)
│       ├── normalizer.py          # Email text cleaning utilities
│       ├── sanitiser.py           # Input sanitisation (XSS / SQL injection defence)
│       ├── pdf_exporter.py        # WeasyPrint HTML → PDF report generator
│       └── training_data.py       # Curated sample emails for the Training Mode
│
├── database/
│   └── schema.sql                 # MySQL DDL to create all tables manually
│
├── frontend/
│   ├── templates/                 # Jinja2 HTML templates
│   │   ├── index.html             # Email submission / analysis page
│   │   ├── dashboard.html         # Analytics dashboard with charts
│   │   ├── rules.html             # Rule management UI (enable/disable/add rules)
│   │   └── training.html          # Training mode (sample phishing exercises)
│   │
│   └── static/
│       ├── css/
│       │   └── main.css           # Application styles + dark-mode theming
│       └── js/
│           ├── analyse.js         # Analysis form logic, result rendering
│           ├── dashboard.js       # Dashboard charts and statistics
│           ├── history.js         # Paginated history table
│           ├── rules.js           # Rule management CRUD operations
│           ├── training.js        # Training mode exercise logic
│           ├── sidebar.js         # Sidebar stats and navigation
│           ├── i18n.js            # English / Swahili translation strings
│           └── theme.js           # Light / dark mode toggle
│
├── exports/                       # Generated PDF reports (auto-created)
├── logs/                          # Application log files (auto-created)
└── tests/
    ├── __init__.py
    ├── test_api.py                # API endpoint integration tests
    ├── test_rule_engine.py        # Email parser and scoring unit tests
    └── test_system.py             # Full pipeline system tests
```

---

## 4. Quick Start

### Prerequisites

- Python 3.12 or newer
- MySQL 8.0 or newer (running locally)
- `pip` package manager

### Step 1 — Clone and set up the environment

```bash
# 1. Enter the project directory
cd phishing_detector

# 2. Create and activate a virtual environment
python -m venv venv
venv\Scripts\activate        # Windows
# source venv/bin/activate   # Linux / macOS

# 3. Install all dependencies
pip install -r requirements.txt
```

### Step 2 — Configure the database

```bash
# Create the MySQL database (run once)
mysql -u root -p < database/schema.sql
```

### Step 3 — Create your `.env` file

```bash
# Windows
copy .env.example .env

# Linux / macOS
cp .env.example .env
```

Edit `.env` and set at minimum:

```ini
DB_PASSWORD=your_mysql_password
SECRET_KEY=any-long-random-string
```

### Step 4 — Start the application

```bash
# Windows one-click
start.bat

# Or manually
python app.py
``

Open your browser at **http://localhost:5000**

> On first startup the application automatically:
> - Creates all database tables (`db.create_all()`)
> - Runs column migrations for any schema updates
> - Seeds / syncs all built-in detection rules from `rules_definitions.py`

---

## 5. Configuration

All configuration is read from the `.env` file at startup.
See `backend/utils/config.py` for the full list of settings and their defaults.

| Variable | Default | Description |
|---|---|---|
| `SECRET_KEY` | `phishguard-v2-...` | Flask session signing key. **Change this in production.** |
| `DEBUG` | `True` | Flask debug mode. Set `False` in production. |
| `LOG_LEVEL` | `INFO` | Python logging level (`DEBUG`, `INFO`, `WARNING`, `ERROR`) |
| `DB_HOST` | `localhost` | MySQL server hostname |
| `DB_PORT` | `3306` | MySQL server port |
| `DB_USER` | `root` | MySQL username |
| `DB_PASSWORD` | *(empty)* | MySQL password |
| `DB_NAME` | `phishguard` | MySQL database name |
| `MAX_EMAIL_SIZE_KB` | `500` | Maximum accepted email size in kilobytes |
| `ANALYSIS_TIMEOUT_SECONDS` | `10` | Per-request pipeline timeout |
| `DEFAULT_LANGUAGE` | `en` | Default explanation language (`en` or `sw`) |

### Connection pool settings (in `config.py`)

```python
SQLALCHEMY_POOL_RECYCLE = 280      # Recycle connections before MySQL's 5-min timeout
SQLALCHEMY_ENGINE_OPTIONS = {
    "pool_pre_ping": True           # Test each connection before use — handles MySQL restarts
}
```

---

## 6. Engine Files Explained

### `email_parser.py` — MIME Parser

**Input:** Raw RFC-2822 email string OR individual fields (sender, subject, body, headers)  
**Output:** `ParsedEmail` dataclass with 50+ populated fields

The parser has two entry points:
- `parse_raw(raw_email)` — parses a complete MIME email string
- `parse_fields(sender, subject, body_text, body_html, headers)` — parses individual form fields

After parsing the raw content, the `_post_process()` method runs automatically:

| Method | What it computes |
|--------|-----------------|
| `_parse_html()` | Visible text, form actions, external images, href-text mismatches, meta-refresh |
| `_extract_urls()` | All HTTP(S) URLs, domain list, risk flags (IP URLs, shorteners, suspicious TLDs) |
| `_detect_personalisation()` | Whether the email uses a real personal name (vs. "Dear Customer") |
| `_extract_authentication()` | SPF / DKIM / DMARC results from Authentication-Results header |
| `_compute_entropy()` | Shannon entropy of the body text |
| `_compute_linguistic_metrics()` | Word count, average word length |

**Important:** `TRUSTED_DOMAINS` in this file is the single source of truth for which sender domains receive automatic legitimacy credit (CRDB, NMB, UDSM, UDOM, and other major Tanzanian institutions). Any subdomain of a trusted domain is also trusted (e.g. `cse.udsm.ac.tz` inherits trust from `udsm.ac.tz`).

---

### `feature_engine.py` — Feature Extractor

**Input:** `ParsedEmail`  
**Output:** `FeatureSet` dataclass (70+ boolean/numeric features)

Groups of features extracted:

| Group | Examples |
|-------|---------|
| URL features | `has_ip_url`, `has_shortener`, `has_suspicious_tld`, `link_text_mismatch_count` |
| Sender features | `sender_uses_free_email`, `sender_domain_typosquatting`, `reply_to_differs` |
| Auth features | `spf_pass`, `dkim_pass`, `dmarc_fail`, `missing_message_id` |
| Content features | `has_urgency_language`, `has_credential_request`, `has_prize_language` |
| HTML features | `has_script_tag`, `has_iframe`, `has_meta_refresh`, `has_form_to_external` |
| Attachment features | `has_dangerous_attachment`, `has_macro_office_file`, `has_double_extension` |
| Linguistic features | `has_excessive_caps`, `has_invisible_unicode`, `body_entropy` |
| Legitimacy features | `has_unsubscribe_header`, `recipient_personally_addressed`, `send_hour_normal` |

**Typosquatting note:** The typosquatting check is skipped entirely when `p.trusted_domain is True`. This prevents legitimate university subdomains (e.g. `library@udom.ac.tz`) from being falsely flagged as impersonating `udsm.ac.tz`.

---

### `rule_engine.py` — Rule Evaluator

**Input:** `ParsedEmail` + optional `FeatureSet`  
**Output:** `List[RuleMatch]`

Rules are loaded from the MySQL `rules` table with a **60-second TTL cache**. Each loaded rule is immediately converted to a `_RuleProxy` plain Python dataclass before caching. This avoids the `DetachedInstanceError` that would occur if live SQLAlchemy ORM objects were cached across request boundaries (when Flask closes the session after each request).

Two types of rule evaluation:

1. **Regex rules** — the rule's `pattern` field contains a regex string.  
   The engine scans only the relevant email fields for each rule category:
   - `url_analysis` → scans URL list and body text
   - `content_keyword` → scans subject, body text, visible HTML text
   - `sender_verification` → scans From header and sender email
   - `header_authentication` → scans all headers and X-Mailer
   - `html_obfuscation` → scans raw HTML body
   - `behavioral` → scans attachment names and body

2. **Programmatic rules** — the rule's `pattern` field contains a sentinel string  
   that maps to a Python method handler. These are used when regex alone is not  
   sufficient (e.g. typosquatting requires string similarity, ALL-CAPS detection  
   requires case-sensitive scanning):

| Sentinel | Handler | What it checks |
|----------|---------|---------------|
| `DISPLAY_DOMAIN_MISMATCH` | `_check_display_domain_mismatch` | Display name contains a known brand but domain doesn't match |
| `TYPOSQUATTING_CHECK` | `_check_typosquatting` | Sender domain is visually similar to a known brand (difflib) |
| `REPLY_TO_MISMATCH` | `_check_reply_to_mismatch` | Reply-To domain differs from From domain |
| `DKIM_MISSING_OR_FAIL` | `_check_dkim` | DKIM-Signature header absent |
| `DMARC_NOT_ENFORCED` | `_check_dmarc` | DMARC=fail in Authentication-Results |
| `LINK_TEXT_HREF_MISMATCH` | `_check_link_mismatch` | Visible link text shows a different domain than the href |
| `HTML_INLINE_STYLE_DENSITY` | `_check_inline_style_density` | More than 20 inline style attributes |
| `SENDING_HOUR_CHECK` | `_check_sending_hour` | Email sent between midnight and 5 AM UTC |
| `EXTERNAL_IMAGE_COUNT` | `_check_external_images` | Images from 3+ distinct external domains |
| `MISSING_MESSAGE_ID` | `_check_missing_message_id` | Message-ID header absent |
| `EXCESSIVE_CAPS_CHECK` | `_check_excessive_caps` | 3+ genuinely ALL-CAPS words (scanned without IGNORECASE) |

---

### `rules_definitions.py` — Built-in Rule Catalogue

Contains `ALL_RULES`: the master list of all built-in detection rules.  
On every startup, `_sync_builtin_rules()` in `database.py` upserts these rules into the database:
- Rules in `ALL_RULES` that already exist in DB are **updated** (weight, pattern, description).
- Rules in `ALL_RULES` not yet in DB are **inserted** as new rows.
- Non-custom rules in DB that are NOT in `ALL_RULES` are **disabled** (preventing stale rules from causing false positives).

Rule categories and weight guide:

| Category | Multiplier | What it covers |
|----------|-----------|---------------|
| `url_analysis` | ×1.4 | URL structure, IP addresses, shorteners, suspicious TLDs |
| `header_authentication` | ×1.3 | SPF/DKIM/DMARC, Message-ID, X-Mailer |
| `sender_verification` | ×1.3 | Domain spoofing, typosquatting, Reply-To mismatches |
| `html_obfuscation` | ×1.2 | Hidden text, iframes, scripts, meta-refresh |
| `behavioral` | ×1.1 | Dangerous attachments, off-hours sending |
| `content_keyword` | ×0.9 | Urgency language, credential requests, prize lures |
| `linguistic_analysis` | ×0.7 | ALL-CAPS, exclamation marks, invisible Unicode |

Weight values: `3.0` = near-certain indicator | `2.5` = very strong | `2.0` = strong |
`1.5` = moderate | `1.0` = weak | `0.5` = very weak (supporting signal only)

---

### `correlation_engine.py` — Composite Pattern Detector

**Input:** `FeatureSet` + `List[RuleMatch]`  
**Output:** `CorrelationResult` (composite_bonus, triggered_composites)

Detects named attack patterns that require **multiple signals to co-occur**:

| Pattern | Signals required | Bonus |
|---------|-----------------|-------|
| Credential Phishing | Suspicious URL + credential request + urgency | +30 |
| Domain Spoofing | Typosquatted domain + SPF failure | +25 |
| Malware Delivery | Dangerous attachment + script tag | +25 |
| Business Email Compromise (corroborated) | Financial request + impersonation + urgency | +20 |
| Business Email Compromise (pure BEC) | Financial request + secrecy demand + urgency | +15 |
| Social Engineering | Prize/authority lure + fear language + external links | +15 |
| Strong Legitimacy Cluster | Personal name + no deception + no suspicious TLD/URL | −20 |

The composite bonus is divided by 5 before being added to the raw score (keeps it proportional).

---

### `legitimacy_engine.py` — Negative Scorer

**Input:** `FeatureSet`  
**Output:** `LegitimacyResult` (legitimacy_deduction, deduction_reasons)

Subtracts from the normalised score when authentic legitimacy signals are present.
The total deduction is capped at 30 points.

| Signal | Deduction | Why it matters |
|--------|-----------|---------------|
| DKIM authenticated | −8 | Cryptographic proof — cannot be forged |
| SPF authenticated | −5 | Sending server is authorised by domain owner |
| Both DKIM + SPF | −3 | Bonus for dual authentication |
| Personalised greeting (real name, not BEC) | −4 | Mass phishing cannot personalise cheaply |
| Proper Message-ID | −3 | Real mail servers always inject well-formed IDs |
| List-Unsubscribe header | −3 | Phishing never includes this (exposes infrastructure) |
| No suspicious URLs | −2 | URLs present but all clean |
| Verified non-free provider + DKIM | −2 | Corporate sender with valid authentication |
| **No phishing signals detected** | **−12** | No urgency, credentials, suspicious URLs, or domain deception — counteracts structural penalties on field-submitted legitimate emails |

---

### `scoring_engine.py` — Risk Calculator

**Input:** `List[RuleMatch]` + `CorrelationResult` + `LegitimacyResult`  
**Output:** `ScoringResult` (risk_score 0–100, classification, confidence)

**Formula:**
```
raw_score      = Σ(rule.weight × category_multiplier)
adjusted_raw   = raw_score + (composite_bonus ÷ 5)
normalised     = 100 × (1 − e^(−0.085 × adjusted_raw))
final_score    = clamp(normalised − legitimacy_deduction, 0, 100)
classification = threshold(final_score)
```

**Classification thresholds:**
- `final_score < 21` → **legitimate**
- `21 ≤ final_score < 55` → **suspicious**
- `final_score ≥ 55` → **phishing**

The exponential normalisation (`k = 0.085`) ensures:
- 1–2 weak rules → ~10–16% (legitimate)
- 3–4 moderate rules → ~22–29% (suspicious)
- Strong signals + composite patterns → 55%+ (phishing)

---

### `explainability_engine.py` — Narrative Generator

**Input:** `ScoringResult` + language code (`en` or `sw`)  
**Output:** Structured dict with narrative, rule cards, category breakdown, recommendations

The output includes:
- A plain-English (or Swahili) paragraph explaining the verdict.
- Severity-ranked cards for each triggered rule with evidence snippets.
- Per-category score breakdown for the UI radar chart.
- Actionable recommendations ("Do NOT click any links…" etc.)

---

### `analysis_pipeline.py` — Orchestrator

Runs all 9 stages in order, measures per-stage timing, handles errors at each stage
(so a failure in one stage does not crash the whole pipeline), persists results to
the database, and returns a single structured JSON response.

Every pipeline run has a unique `trace_id` (UUID4) that links the HTTP response,
the log entry, and the database row for audit purposes.

---

### `database.py` — ORM Models

Five SQLAlchemy models:

| Model | Table | Description |
|-------|-------|-------------|
| `Email` | `emails` | Raw submission data |
| `AnalysisResult` | `analysis_results` | Scores, classification, features JSON |
| `Rule` | `rules` | Detection rule catalogue |
| `TriggeredRule` | `triggered_rules` | Audit trail of which rules fired per analysis |
| `UserFeedback` | `user_feedback` | Analyst corrections (true/false positive marking) |

The `init_db()` function (called on every startup) runs three operations:
1. `db.create_all()` — create any missing tables
2. `_run_column_migrations()` — add any columns that were added to models after initial deployment
3. `_sync_builtin_rules()` — upsert all rules from `rules_definitions.py` into the `rules` table

---

## 7. Pipeline Flow

```
POST /api/analyse  (JSON payload)
         |
[1] EmailParser.parse_fields()  OR  parse_raw()
         |  →  ParsedEmail  (sender, URLs, HTML features, auth results, etc.)
         |
[2] normalizer.normalize_email_content()
         |  →  clean whitespace, unify line endings
         |
[3] FeatureEngine.extract()
         |  →  FeatureSet  (70+ signal booleans and integers)
         |
[4] RuleEngine.evaluate()
         |  →  List[RuleMatch]  (rules loaded from DB with 60s TTL cache)
         |
[5] CorrelationEngine.correlate()
         |  →  CorrelationResult  (composite patterns, bonus/deduction)
         |
[6] LegitimacyEngine.evaluate()
         |  →  LegitimacyResult  (deductions, signal list)
         |
[7] ScoringEngine.score()
         |  →  ScoringResult  (risk_score 0-100, classification, confidence)
         |
[8] ExplainabilityEngine.explain()
         |  →  dict  (narrative, rule cards, recommendations)
         |
[9] _persist()  →  MySQL  (Email + AnalysisResult + TriggeredRule rows)
         |
JSON response  →  { success, risk_score, classification, triggered_rules, explanation, ... }
```

---

## 8. Scoring Model

The scoring system is calibrated to avoid the most common false-positive scenarios
in legitimate Tanzanian business emails:

| Email type | Typical score | Classification |
|------------|--------------|---------------|
| UDSM / UDOM institutional email | 0–5% | Legitimate |
| Personal Gmail with personalised name | 0–10% | Legitimate |
| Business notification (Dear Customer) from Yahoo | 15–21% | Legitimate |
| Document sharing link with time pressure | 22–30% | Suspicious |
| Unknown sender, generic greeting, link expiry | 25–35% | Suspicious |
| CRDB/NMB bank phishing from .xyz/.tk domain | 75–90% | Phishing |
| Classic credential phishing with IP URL | 80–95% | Phishing |
| BEC wire transfer (personalised + secrecy) | 55–65% | Phishing |

---

## 9. API Reference

All endpoints are under the `/api/` prefix.

### POST `/api/analyse` — Analyse an email

**Request body (JSON):**
```json
{
  "sender":    "From: header value",
  "subject":   "Email subject",
  "body_text": "Plain text body",
  "body_html": "<html>HTML body</html>",
  "headers":   "Raw header block (optional)",
  "raw_email": "Complete RFC-2822 email (overrides individual fields)",
  "language":  "en"
}
```

At least one of `raw_email`, `body_text`, `body_html`, `subject`, or `sender` must be provided.

**Response (200 OK):**
```json
{
  "success": true,
  "trace_id": "uuid-v4",
  "risk_score": 87.5,
  "classification": "phishing",
  "confidence": 0.82,
  "processing_ms": 42.3,
  "rules_triggered": 7,
  "triggered_rules": [
    {
      "rule_name": "IP address as hostname",
      "severity": "high",
      "score": 4.2,
      "evidence": "[url_list] http://192.168.1.1/login"
    }
  ],
  "composite_patterns": [...],
  "legitimacy_signals": [...],
  "explanation": {
    "narrative": "WARNING: This email has strong indicators...",
    "recommendations": "Do NOT click any links...",
    "category_breakdown": [...],
    "triggered_rules": [...]
  }
}
```

---

### GET `/api/history` — Paginated analysis history

Query parameters: `page` (default 1), `per_page` (default 20, max 100),
`classification` (`legitimate` | `suspicious` | `phishing` | `all`)

---

### GET `/api/stats` — Dashboard statistics

Returns total counts, classification breakdown, top-10 triggered rules,
average risk score, and 14-day daily trend.

---

### GET `/api/rules` — List all rules

Query parameters: `category` (filter by category), `enabled` (`true`|`false`|`all`)

---

### POST `/api/rules` — Create a custom rule

```json
{
  "name":        "My custom rule",
  "category":    "content_keyword",
  "weight":      1.5,
  "pattern":     "\\b(my|pattern)\\b",
  "description": "Optional description"
}
```

---

### PATCH `/api/rules/<id>` — Toggle or update a rule

```json
{
  "is_enabled":  false,
  "weight":      2.0,
  "description": "Updated description"
}
```

---

### GET `/api/export/<analysis_id>` — Export PDF report

Returns a PDF file of the analysis report. Requires WeasyPrint to be installed.

---

### POST `/api/feedback` — Submit analyst feedback

```json
{
  "analysis_result_id": 42,
  "is_correct":         false,
  "correct_label":      "legitimate",
  "comment":            "This is a legitimate bank notification"
}
```

---

### GET `/api/training` — Get training sample emails

Query parameter: `type` (`phishing` | `legitimate` | `suspicious` | `all`)

---

## 10. Database Schema

The schema is in `database/schema.sql`. Run it once before starting the app:

```bash
mysql -u root -p < database/schema.sql
```

The app's `init_db()` function also calls `db.create_all()` which creates tables
automatically if they don't exist, so the SQL file is optional for fresh installs.

**Tables:**

| Table | Purpose |
|-------|---------|
| `emails` | Raw submission: sender, recipient, subject, body, headers, IP |
| `analysis_results` | Scores, classification, features JSON, trace_id, processing time |
| `rules` | Detection rule catalogue (built-in + custom, enable/disable toggle) |
| `triggered_rules` | Audit trail linking each rule fire to an analysis result |
| `user_feedback` | Analyst corrections for measuring false positive/negative rates |

---

## 11. Detection Rules

Built-in rules are defined in `backend/engine/rules_definitions.py` and are synced
to the database on every startup. Rules can be managed from the **Rules** page in
the UI (`/rules`) — you can enable/disable rules, adjust weights, and add custom
regex rules.

**Rule categories:**

| Category | Rules | Example |
|----------|-------|---------|
| `url_analysis` | URL_001–URL_014 | IP as hostname, URL shortener, suspicious TLD |
| `content_keyword` | KW_001–KW_006, SOC_001–SOC_007, URGENCY_002 | Urgency language, credential harvesting, prize lures |
| `sender_verification` | SND_001–SND_005 | Display-name brand mismatch, typosquatting, Reply-To mismatch |
| `header_authentication` | HDR_003–HDR_010 | DMARC fail, X-Mailer spam tool, missing Message-ID |
| `html_obfuscation` | HTML_001–HTML_010 | Link text mismatch, iframe, meta-refresh, hidden text |
| `behavioral` | BEH_001–BEH_009, ATT_001–ATT_005 | Dangerous attachments, macro files, off-hours send |
| `linguistic_analysis` | LING_001–LING_005 | ALL-CAPS words, exclamation marks, invisible Unicode |

---

## 12. Frontend Pages

| Route | Template | Description |
|-------|----------|-------------|
| `/` | `index.html` | Main analysis page — paste/type email and get results |
| `/dashboard` | `dashboard.html` | Charts: total emails, classification breakdown, top rules, trend |
| `/rules` | `rules.html` | Rule management — toggle, weight edit, add custom rules |
| `/training` | `training.html` | Training mode — guided phishing exercises with hints |

All pages support **English and Swahili** via `i18n.js`. The toggle is in the
top navigation bar. Language preference is saved in `localStorage`.

Dark/light mode is available via the theme toggle (saved in `localStorage`).

---

## 13. Testing

Tests are in the `tests/` directory and use `pytest`.

```bash
# Run all tests
pytest tests/ -v

# Run only API tests
pytest tests/test_api.py -v

# Run only engine unit tests
pytest tests/test_rule_engine.py tests/test_system.py -v
```

**Test files:**

| File | What it tests |
|------|--------------|
| `test_api.py` | All REST API endpoints (uses Flask test client + SQLite in-memory DB) |
| `test_rule_engine.py` | EmailParser, ScoringEngine, input sanitiser |
| `test_system.py` | Full pipeline integration: parser, features, correlation, legitimacy, scoring, API |

The test configuration in `setup.cfg` uses `TestingConfig` which replaces MySQL with
an in-memory SQLite database — no MySQL connection is needed to run tests.

---

## 14. Troubleshooting

### App shows `503 Database unavailable`

MySQL is not running or the credentials in `.env` are wrong.

```bash
# Windows: check MySQL service
services.msc   # look for MySQL80

# Linux / macOS
sudo systemctl status mysql
sudo service mysql start
```

Verify the `.env` credentials match your MySQL setup.

---

### `POST /api/analyse` returns `500`

Check the Flask console log for the full traceback. Common causes:

1. **First startup** — the DB tables or rule columns are being created.  
   Wait a moment and retry.

2. **Rule cache issue** — restart the Flask server to flush the 60-second rule cache.

3. **Full error in logs** — check `logs/phishguard.log` for details.

---

### Rules are showing old weights / stale behaviour

The `_sync_builtin_rules()` function runs on every startup and syncs `rules_definitions.py`
to the database. If you edited `rules_definitions.py`, restart the server to apply changes.

To force a full re-sync manually:

```python
# In a Flask shell
from app import create_app
app = create_app()
with app.app_context():
    from backend.models.database import _sync_builtin_rules
    _sync_builtin_rules()
```

---

### PDF export fails

Install WeasyPrint's system dependencies:

```bash
# Ubuntu / Debian
sudo apt-get install -y weasyprint

# Or via pip (may require GTK on Windows)
pip install weasyprint
```

---

### False positive — legitimate email scored as suspicious/phishing

1. Check which rules fired (`triggered_rules` in the API response).
2. If structural rules fired (DKIM absent, Missing Message-ID) without any content
   signals — this is expected for field-submitted emails; the "No Phishing Signals
   Detected" legitimacy deduction (−12) should have compensated.
3. If a rule has too aggressive a pattern, disable it from the **Rules** page (`/rules`).
4. Submit feedback via `POST /api/feedback` to track false positive rates.

---

## License

Built as a research and educational tool for Tanzanian university computer science
departments. Not for commercial use without permission.
