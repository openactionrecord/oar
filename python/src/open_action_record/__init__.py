"""Verify Open Action Records (OAR): signed proof of what an AI agent's action actually changed, and who approved it."""

from .verify import BundleError, RecordReport, Report, outcomes, parse_bundle, verify_bundle

__all__ = ["BundleError", "RecordReport", "Report", "outcomes", "parse_bundle", "verify_bundle"]
__version__ = "0.1.1"
