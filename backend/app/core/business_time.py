"""
Business (local) time for the detection features.

Timestamps are stored as naive UTC everywhere (datetime.utcnow()). "What hour did this user log in"
and "was it a weekend" only mean something in the programme's own time zone: a Nairobi user who
starts at 08:00 EAT is recorded at 05:00 UTC, which must not count as off-hours. So every feature
that reads a clock hour or a weekday converts to settings.BUSINESS_TIMEZONE first.

Storage stays UTC; only the interpretation is local.
"""
from datetime import datetime, timezone
from zoneinfo import ZoneInfo

from app.core.config import settings

BUSINESS_TZ = ZoneInfo(settings.BUSINESS_TIMEZONE)


def to_local(utc_naive: datetime) -> datetime:
    """Naive UTC (as stored) -> naive local business time."""
    return utc_naive.replace(tzinfo=timezone.utc).astimezone(BUSINESS_TZ).replace(tzinfo=None)


def to_utc(local_naive: datetime) -> datetime:
    """Naive local business time -> naive UTC (as stored)."""
    return local_naive.replace(tzinfo=BUSINESS_TZ).astimezone(timezone.utc).replace(tzinfo=None)


def local_now() -> datetime:
    return to_local(datetime.utcnow())


def tz_label() -> str:
    """Short name for display, e.g. 'EAT'."""
    return datetime.now(BUSINESS_TZ).tzname() or settings.BUSINESS_TIMEZONE
