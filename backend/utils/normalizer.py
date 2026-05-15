"""
backend/utils/normalizer.py
============================
Text normalization utilities for PhishGuard v2.

Normalizes email body content to reduce noise before analysis:
  - Unify line endings (CRLF → LF)
  - Collapse excessive blank lines
  - Strip trailing whitespace per line
  - Trim leading/trailing whitespace
"""

import re


def normalize_email_content(text: str) -> str:
    """
    Normalize raw email body text for consistent downstream analysis.

    Args:
        text: Raw body_text or body_html string from the parser.

    Returns:
        Cleaned string; empty string if input is None or empty.
    """
    if not text:
        return ""

    # Normalize Windows (CRLF) and old Mac (CR) line endings to Unix (LF)
    text = text.replace("\r\n", "\n").replace("\r", "\n")

    # Collapse 3+ consecutive blank lines into at most 2
    text = re.sub(r"\n{3,}", "\n\n", text)

    # Strip trailing whitespace from every line (preserves indentation)
    lines = [line.rstrip() for line in text.split("\n")]
    text = "\n".join(lines)

    # Remove leading and trailing whitespace from the whole document
    return text.strip()
