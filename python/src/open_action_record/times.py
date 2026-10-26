"""Timestamps in the exact form the TypeScript implementation writes: RFC 3339 UTC with milliseconds."""

from __future__ import annotations

from datetime import datetime, timezone


def iso(dt: datetime) -> str:
    dt = dt.astimezone(timezone.utc)
    return dt.strftime("%Y-%m-%dT%H:%M:%S.") + f"{dt.microsecond // 1000:03d}Z"


def iso_now() -> str:
    return iso(datetime.now(timezone.utc))


def parse(value: str) -> datetime:
    return datetime.fromisoformat(value.replace("Z", "+00:00"))
