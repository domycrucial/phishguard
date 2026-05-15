"""
============================================================
backend/utils/sanitiser.py
Input Sanitisation and Validation Utilities for PhishGuard.
Provides:
  - sanitise_input(): strips dangerous HTML/JS, enforces length
  - validate_rule_input(): validates custom rule creation fields
Security goals:
  - Prevent XSS by stripping script tags from text inputs
  - Prevent SQL injection (handled by SQLAlchemy ORM, but we
    also strip SQL comment markers for defence in depth)
  - Enforce maximum field lengths to prevent DoS
============================================================
"""

# Standard library imports
import re           # Regex for dangerous pattern removal
import html         # HTML entity escaping
from typing import List, Optional


# ══════════════════════════════════════════════════════════
#  INPUT SANITISER
# ══════════════════════════════════════════════════════════

# Regex patterns for XSS prevention
SCRIPT_TAG_PATTERN     = re.compile(r"<script[^>]*>.*?</script>", re.IGNORECASE | re.DOTALL)
# Matches full <script>...</script> blocks for removal

EVENT_HANDLER_PATTERN  = re.compile(r"\s+on\w+\s*=\s*['\"][^'\"]*['\"]", re.IGNORECASE)
# Matches inline event handlers like onclick="...", onload="..."

JAVASCRIPT_PROTOCOL    = re.compile(r"javascript\s*:", re.IGNORECASE)
# Matches javascript: in href/src attributes

SQL_COMMENT_PATTERN    = re.compile(r"(--|;|/\*|\*/|xp_|EXEC\s+|UNION\s+SELECT)", re.IGNORECASE)
# Common SQL injection markers — removed as extra defence layer


def sanitise_input(
    value: str,
    max_length: int = 10_000,
    allow_html: bool = False
) -> str:
    """
    Sanitise a string input field.

    Args:
        value:      The raw input string to sanitise.
        max_length: Maximum allowed length (truncates if exceeded).
        allow_html: If True, allow HTML markup (for body_html fields).
                    If False, strip all HTML tags and escape entities.

    Returns:
        Sanitised string, safe for storage and display.
    """
    if not isinstance(value, str):
        return ""   # Non-string inputs become empty string

    # --- Step 1: Always remove <script> blocks regardless of allow_html ---
    value = SCRIPT_TAG_PATTERN.sub("", value)

    # --- Step 2: Always remove inline event handlers (onclick, onload, etc.) ---
    value = EVENT_HANDLER_PATTERN.sub("", value)

    # --- Step 3: Always replace javascript: protocol references ---
    value = JAVASCRIPT_PROTOCOL.sub("blocked:", value)

    if not allow_html:
        # --- Step 4a: Strip all HTML tags for plain-text fields ---
        value = re.sub(r"<[^>]+>", "", value)   # Remove all HTML tags
        value = html.unescape(value)             # Convert &amp; → & etc.
        value = value.strip()                    # Remove leading/trailing whitespace

    # --- Step 5: Remove SQL injection markers (defence in depth) ---
    # Note: SQLAlchemy's parameterised queries are the primary protection;
    # this is an extra layer for any dynamic query segments.
    # We only apply this to short fields (not email bodies where -- is valid text)
    if max_length <= 1024:
        value = SQL_COMMENT_PATTERN.sub("", value)

    # --- Step 6: Enforce maximum length (truncate without raising exception) ---
    if len(value) > max_length:
        value = value[:max_length]   # Silent truncation

    return value


# ══════════════════════════════════════════════════════════
#  RULE INPUT VALIDATOR
# ══════════════════════════════════════════════════════════

# Valid rule categories (must match the SQLAlchemy Enum)
VALID_CATEGORIES = {
    "url_analysis",
    "content_keyword",
    "sender_verification",
    "header_authentication",
    "html_obfuscation",
    "behavioral",
    "linguistic_analysis",
}


def validate_rule_input(data: dict) -> List[str]:
    """
    Validate the JSON body for POST /api/rules (custom rule creation).

    Args:
        data: Parsed JSON dict from the request body.

    Returns:
        List of error strings. Empty list means validation passed.
    """
    errors: List[str] = []   # Accumulate all validation errors

    # --- Validate 'name' ---
    name = data.get("name", "").strip()
    if not name:
        errors.append("Rule 'name' is required.")
    elif len(name) > 256:
        errors.append("Rule 'name' must be 256 characters or fewer.")

    # --- Validate 'category' ---
    category = data.get("category", "")
    if not category:
        errors.append("Rule 'category' is required.")
    elif category not in VALID_CATEGORIES:
        errors.append(
            f"Invalid category '{category}'. "
            f"Valid options: {', '.join(sorted(VALID_CATEGORIES))}"
        )

    # --- Validate 'weight' ---
    weight_raw = data.get("weight")
    if weight_raw is None:
        errors.append("Rule 'weight' is required.")
    else:
        try:
            weight = float(weight_raw)
            if not (0.1 <= weight <= 5.0):
                errors.append("Rule 'weight' must be between 0.1 and 5.0.")
        except (ValueError, TypeError):
            errors.append("Rule 'weight' must be a number.")

    # --- Validate 'pattern' (regex syntax check) ---
    pattern = data.get("pattern", "").strip()
    if not pattern:
        errors.append("Rule 'pattern' (regex) is required.")
    else:
        try:
            re.compile(pattern)   # Attempt to compile — raises re.error if invalid
        except re.error as exc:
            errors.append(f"Rule 'pattern' is not a valid regex: {exc}")
        if len(pattern) > 1000:
            errors.append("Rule 'pattern' must be 1000 characters or fewer.")

    return errors
