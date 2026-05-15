-- ============================================================
-- PhishGuard Database Schema for MySQL 8.0+
-- File: database/schema.sql
-- Description: Creates the phishguard database and all tables.
-- Run this once to initialise the database before starting the app.
-- Usage:  mysql -u root -p < database/schema.sql
-- ============================================================

-- Create the database if it doesn't exist
CREATE DATABASE IF NOT EXISTS phishguard
  CHARACTER SET utf8mb4        -- utf8mb4 supports full Unicode including emoji
  COLLATE utf8mb4_unicode_ci;  -- Case-insensitive, accent-sensitive collation

-- Use the database
USE phishguard;

-- ─────────────────────────────────────────────────────────────
-- TABLE: emails
-- Stores each raw email submission.
-- ─────────────────────────────────────────────────────────────
CREATE TABLE IF NOT EXISTS emails (
  id           INT            UNSIGNED NOT NULL AUTO_INCREMENT,
  sender       VARCHAR(512)   DEFAULT NULL COMMENT 'From: header address',
  recipient    VARCHAR(512)   DEFAULT NULL COMMENT 'To: header address',
  subject      VARCHAR(1024)  DEFAULT NULL COMMENT 'Email subject line',
  body_text    LONGTEXT       DEFAULT NULL COMMENT 'Decoded plain-text body',
  body_html    LONGTEXT       DEFAULT NULL COMMENT 'HTML body content',
  raw_headers  TEXT           DEFAULT NULL COMMENT 'Full RFC-2822 headers as text',
  submitted_at DATETIME       NOT NULL DEFAULT CURRENT_TIMESTAMP COMMENT 'UTC submission timestamp',
  ip_address   VARCHAR(45)    DEFAULT NULL COMMENT 'Submitter IP (supports IPv6)',
  language     VARCHAR(10)    NOT NULL DEFAULT 'en' COMMENT 'en or sw',
  PRIMARY KEY (id),
  INDEX idx_submitted_at (submitted_at)  -- Speeds up date-range queries for the dashboard
) ENGINE=InnoDB DEFAULT CHARSET=utf8mb4 COLLATE=utf8mb4_unicode_ci
  COMMENT='Stores each raw email submission for analysis';

-- ─────────────────────────────────────────────────────────────
-- TABLE: analysis_results
-- Stores computed risk scores and classifications.
-- ─────────────────────────────────────────────────────────────
CREATE TABLE IF NOT EXISTS analysis_results (
  id               INT           UNSIGNED NOT NULL AUTO_INCREMENT,
  email_id         INT           UNSIGNED NOT NULL COMMENT 'FK → emails.id',
  risk_score       FLOAT         NOT NULL COMMENT 'Normalised 0–100 risk score',
  classification   ENUM('legitimate','suspicious','phishing')
                                 NOT NULL COMMENT 'Classified result',
  confidence       FLOAT         NOT NULL DEFAULT 0.0 COMMENT '0–1 confidence level',
  category_scores  TEXT          DEFAULT NULL COMMENT 'JSON dict of per-category scores',
  explanation      TEXT          DEFAULT NULL COMMENT 'Human-readable narrative',
  legitimacy_score FLOAT         NOT NULL DEFAULT 0.0 COMMENT 'Legitimacy deduction applied',
  composite_bonus  FLOAT         NOT NULL DEFAULT 0.0 COMMENT 'Correlation composite bonus',
  features_json    LONGTEXT      DEFAULT NULL COMMENT 'Full feature set JSON for audit',
  processing_time  FLOAT         DEFAULT NULL COMMENT 'Processing time in milliseconds',
  analysed_at      DATETIME      NOT NULL DEFAULT CURRENT_TIMESTAMP COMMENT 'UTC completion timestamp',
  PRIMARY KEY (id),
  FOREIGN KEY (email_id) REFERENCES emails(id) ON DELETE CASCADE,
  INDEX idx_classification (classification),  -- Fast count by class for dashboard
  INDEX idx_analysed_at (analysed_at)
) ENGINE=InnoDB DEFAULT CHARSET=utf8mb4 COLLATE=utf8mb4_unicode_ci
  COMMENT='Computed analysis results for each submitted email';

-- ─────────────────────────────────────────────────────────────
-- TABLE: rules
-- Detection rule definitions (seeded + user-created).
-- ─────────────────────────────────────────────────────────────
CREATE TABLE IF NOT EXISTS rules (
  id           INT           UNSIGNED NOT NULL AUTO_INCREMENT,
  rule_id      VARCHAR(64)   NOT NULL COMMENT 'Human-readable unique ID, e.g. URL_001',
  name         VARCHAR(256)  NOT NULL COMMENT 'Short descriptive rule name',
  category     ENUM(
    'url_analysis','content_keyword','sender_verification',
    'header_authentication','html_obfuscation','behavioral',
    'linguistic_analysis'
  )             NOT NULL COMMENT 'Rule logical grouping',
  weight       FLOAT         NOT NULL DEFAULT 1.0 COMMENT 'Scoring weight (0.1–5.0)',
  description  TEXT          DEFAULT NULL COMMENT 'Explanation of what the rule detects',
  pattern      TEXT          DEFAULT NULL COMMENT 'Regex or sentinel pattern string',
  is_enabled   TINYINT(1)    NOT NULL DEFAULT 1 COMMENT '1=active, 0=disabled',
  is_custom    TINYINT(1)    NOT NULL DEFAULT 0 COMMENT '1=user-created, 0=system rule',
  created_at   DATETIME      NOT NULL DEFAULT CURRENT_TIMESTAMP,
  PRIMARY KEY (id),
  UNIQUE KEY uq_rule_id (rule_id),            -- Ensure no duplicate rule IDs
  INDEX idx_category (category),
  INDEX idx_enabled (is_enabled)
) ENGINE=InnoDB DEFAULT CHARSET=utf8mb4 COLLATE=utf8mb4_unicode_ci
  COMMENT='Detection rule definitions; seeded on first startup';

-- ─────────────────────────────────────────────────────────────
-- TABLE: triggered_rules
-- Junction table recording which rules fired per analysis.
-- ─────────────────────────────────────────────────────────────
CREATE TABLE IF NOT EXISTS triggered_rules (
  id                 INT     UNSIGNED NOT NULL AUTO_INCREMENT,
  analysis_result_id INT     UNSIGNED NOT NULL COMMENT 'FK → analysis_results.id',
  rule_id            INT     UNSIGNED NOT NULL COMMENT 'FK → rules.id',
  evidence           VARCHAR(500) DEFAULT NULL COMMENT 'Extracted snippet causing the match',
  score_contribution FLOAT   NOT NULL DEFAULT 0.0 COMMENT 'Weighted score contribution',
  PRIMARY KEY (id),
  FOREIGN KEY (analysis_result_id) REFERENCES analysis_results(id) ON DELETE CASCADE,
  FOREIGN KEY (rule_id)            REFERENCES rules(id) ON DELETE CASCADE,
  INDEX idx_analysis (analysis_result_id),
  INDEX idx_rule     (rule_id)              -- Fast lookup for heatmap aggregate query
) ENGINE=InnoDB DEFAULT CHARSET=utf8mb4 COLLATE=utf8mb4_unicode_ci
  COMMENT='Records which rules triggered for each analysis result';

-- ─────────────────────────────────────────────────────────────
-- TABLE: user_feedback
-- Stores analyst feedback on classification accuracy.
-- ─────────────────────────────────────────────────────────────
CREATE TABLE IF NOT EXISTS user_feedback (
  id                 INT     UNSIGNED NOT NULL AUTO_INCREMENT,
  analysis_result_id INT     UNSIGNED NOT NULL COMMENT 'FK → analysis_results.id',
  is_correct         TINYINT(1) NOT NULL COMMENT '1=user agrees with classification',
  correct_label      ENUM('legitimate','suspicious','phishing')
                             DEFAULT NULL COMMENT "User's suggested correct label",
  comment            TEXT    DEFAULT NULL COMMENT 'Optional free-text analyst comment',
  submitted_at       DATETIME NOT NULL DEFAULT CURRENT_TIMESTAMP,
  PRIMARY KEY (id),
  UNIQUE KEY uq_feedback_per_analysis (analysis_result_id),  -- One feedback per analysis
  FOREIGN KEY (analysis_result_id) REFERENCES analysis_results(id) ON DELETE CASCADE
) ENGINE=InnoDB DEFAULT CHARSET=utf8mb4 COLLATE=utf8mb4_unicode_ci
  COMMENT='Analyst feedback for false positive/negative tracking';

-- ─────────────────────────────────────────────────────────────
-- GRANT PRIVILEGES (optional — run as root if needed)
-- Creates a dedicated phishguard DB user for least-privilege access
-- ─────────────────────────────────────────────────────────────
-- CREATE USER IF NOT EXISTS 'phishguard_user'@'localhost' IDENTIFIED BY 'changeme_in_production';
-- GRANT SELECT, INSERT, UPDATE, DELETE, CREATE, DROP, INDEX ON phishguard.* TO 'phishguard_user'@'localhost';
-- FLUSH PRIVILEGES;

SELECT 'PhishGuard schema created successfully.' AS status;
