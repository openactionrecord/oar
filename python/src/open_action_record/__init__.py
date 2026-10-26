"""Write and verify Open Action Records (OAR): signed proof of what an AI agent's action actually changed, and who approved it."""

from .keys import SigningKey, generate_signing_key, load_or_create_key, public_keys
from .recorder import ActionHandle, Recorder, RunResult, build_bundle, commitment_for
from .sealer import LocalSealer
from .verify import BundleError, RecordReport, Report, outcomes, parse_bundle, verify_bundle

__all__ = [
    "ActionHandle", "BundleError", "LocalSealer", "RecordReport", "Recorder", "Report", "RunResult", "SigningKey",
    "build_bundle", "commitment_for", "generate_signing_key", "load_or_create_key", "outcomes", "parse_bundle",
    "public_keys", "verify_bundle",
]
__version__ = "0.2.0"
