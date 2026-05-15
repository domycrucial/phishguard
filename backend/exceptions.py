"""
backend/exceptions.py
=====================
Custom exception hierarchy for PhishGuard v2.

Each pipeline stage raises a specific exception so the
analysis_pipeline can catch them individually and produce
a meaningful error response without masking bugs.
"""


class PhishGuardError(Exception):
    """Base class for all PhishGuard-specific errors."""
    pass


class ParsingError(PhishGuardError):
    """Raised when MIME email parsing fails unrecoverably."""
    pass


class FeatureExtractionError(PhishGuardError):
    """Raised when feature extraction fails for a parsed email."""
    pass


class RuleEvaluationError(PhishGuardError):
    """Raised when the rule engine encounters a fatal error."""
    pass


class ScoringError(PhishGuardError):
    """Raised when the scoring engine cannot produce a result."""
    pass


class NormalizationError(PhishGuardError):
    """Raised when content normalization fails."""
    pass
