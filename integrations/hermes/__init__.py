"""Hermes Agent plugin: Open Action Records for every approval decision.

The implementation lives in the open-action-record package (open_action_record.hermes); this folder lets
`hermes plugins install openactionrecord/oar/integrations/hermes` install it, with Hermes fetching the package.
"""

from open_action_record.hermes import register  # noqa: F401
