# timed_lock.py
"""
Helpers for time-lock: parse human durations and compute unix timestamps.
Supported duration formats: '<N>s' (seconds), '<N>m' (minutes), '<N>h' (hours), '<N>d' (days).
Also supports integer seconds (as string) and None.
All times are displayed in Indian Standard Time (IST, UTC+5:30).
"""

import time
from datetime import datetime, timedelta
from typing import Optional, Tuple


def parse_duration_to_seconds(s: Optional[str]) -> Optional[int]:
    """
    Parse a duration string like '30s', '5m', '2h', '1d' into an integer number of seconds.
    If s is None or empty, returns None.
    If s is purely numeric, treat as seconds.
    """
    if s is None:
        return None
    s = s.strip().lower()
    if s == "":
        return None
    # purely numeric -> seconds
    if s.isdigit():
        return int(s)
    # last char indicates unit
    unit = s[-1]
    try:
        val = int(s[:-1])
    except Exception:
        raise ValueError(f"Invalid duration value: {s}")
    if unit == "s":
        return val
    if unit == "m":
        return val * 60
    if unit == "h":
        return val * 3600
    if unit == "d":
        return val * 86400
    raise ValueError(f"Unknown duration unit in '{s}'. Use s/m/h/d.")


def compute_time_window(unlock_in: Optional[str] = None, expire_in: Optional[str] = None) -> Tuple[Optional[int], Optional[int]]:
    """
    Given human durations (unlock_in, expire_in) relative to now, compute absolute
    unix timestamps (unlock_after, expires_at). Returns (unlock_after_ts, expires_at_ts).
    If a value is None, the corresponding timestamp is None.
    Example: compute_time_window(unlock_in='5m', expire_in='1h')
    """
    now = int(time.time())
    unlock_after = None
    expires_at = None

    us = parse_duration_to_seconds(unlock_in)
    es = parse_duration_to_seconds(expire_in)

    if us is not None:
        unlock_after = now + us
    if es is not None:
        expires_at = now + es

    # If both provided, ensure unlock_after < expires_at
    if (unlock_after is not None) and (expires_at is not None):
        if unlock_after >= expires_at:
            raise ValueError("unlock_in must be less than expire_in (unlock must occur before expiry).")

    return unlock_after, expires_at


def format_ts(ts: Optional[int]) -> str:
    """
    Return human readable string for a unix timestamp in IST (Indian Standard Time, UTC+5:30).
    Returns 'None' if ts is None.
    """
    if ts is None:
        return "None"
    # IST is UTC+5:30 = 5.5 hours = 19800 seconds
    ist_offset = timedelta(hours=5, minutes=30)
    utc_dt = datetime.utcfromtimestamp(ts)
    ist_dt = utc_dt + ist_offset
    return ist_dt.strftime("%Y-%m-%d %H:%M:%S IST")
