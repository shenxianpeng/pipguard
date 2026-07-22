"""Release age heuristic — detect late file additions within PyPI's 14-day window.

PyPI now rejects new file uploads to releases older than 14 days (July 2026).
However, within that 14-day window an attacker who compromises publishing
credentials can still add malicious files (e.g. a new wheel) to an existing
release. This module queries the PyPI JSON API to detect such anomalies.

A release is flagged when:
- The newest file was uploaded significantly later than the oldest file
  (default threshold: 3 days).

This is a LOW-confidence signal — many legitimate projects add platform-specific
wheels over several days after a release. It becomes more suspicious when combined
with other behavioural findings.
"""

from __future__ import annotations

import json
import urllib.request
from dataclasses import dataclass
from datetime import datetime, timezone
from typing import List, Optional

from .models import Finding, RiskLevel

# Default threshold: if the newest file is more than this many days after the
# oldest file in the same release, flag it.
DEFAULT_STALENESS_THRESHOLD_DAYS = 3

_PYPI_JSON_URL = "https://pypi.org/pypi/{name}/{version}/json"
_PYPI_TIMEOUT = 5  # seconds


@dataclass
class ReleaseAgeInfo:
    """Metadata about file upload timing for a release."""

    oldest_upload: Optional[datetime] = None
    newest_upload: Optional[datetime] = None
    file_count: int = 0

    @property
    def upload_span_days(self) -> float:
        """Number of days between the oldest and newest file upload."""
        if self.oldest_upload and self.newest_upload:
            delta = self.newest_upload - self.oldest_upload
            return delta.total_seconds() / 86400.0
        return 0.0


def query_release_age(
    package_name: str,
    version: str,
    timeout: float = _PYPI_TIMEOUT,
) -> Optional[ReleaseAgeInfo]:
    """Query PyPI JSON API for upload timestamps of a release's files.

    Returns None on network error, timeout, or if the release is not found.
    """
    if not package_name or not version:
        return None

    url = _PYPI_JSON_URL.format(name=package_name, version=version)
    try:
        req = urllib.request.Request(url, headers={"Accept": "application/json"})
        with urllib.request.urlopen(req, timeout=timeout) as resp:
            raw = resp.read().decode("utf-8", errors="replace")
    except Exception:
        return None

    try:
        data = json.loads(raw)
    except json.JSONDecodeError:
        return None

    return _parse_release_timestamps(data)


def _parse_release_timestamps(data: dict) -> Optional[ReleaseAgeInfo]:
    """Extract oldest/newest upload_time from PyPI JSON response."""
    urls = data.get("urls", [])
    if not urls:
        return None

    timestamps: List[datetime] = []
    for file_info in urls:
        upload_time_str = file_info.get("upload_time_iso_8601") or file_info.get("upload_time")
        if not upload_time_str:
            continue
        try:
            # PyPI returns ISO 8601 timestamps; normalize to UTC
            ts = _parse_timestamp(upload_time_str)
            if ts:
                timestamps.append(ts)
        except (ValueError, TypeError):
            continue

    if not timestamps:
        return None

    return ReleaseAgeInfo(
        oldest_upload=min(timestamps),
        newest_upload=max(timestamps),
        file_count=len(timestamps),
    )


def _parse_timestamp(ts_str: str) -> Optional[datetime]:
    """Parse a PyPI timestamp string into a timezone-aware datetime."""
    # Try ISO 8601 with timezone
    ts_str = ts_str.strip()
    if ts_str.endswith("Z"):
        ts_str = ts_str[:-1] + "+00:00"
    try:
        dt = datetime.fromisoformat(ts_str)
        if dt.tzinfo is None:
            dt = dt.replace(tzinfo=timezone.utc)
        return dt
    except ValueError:
        pass
    # Fallback: PyPI's older format "YYYY-MM-DDTHH:MM:SS"
    try:
        dt = datetime.strptime(ts_str, "%Y-%m-%dT%H:%M:%S")
        return dt.replace(tzinfo=timezone.utc)
    except ValueError:
        return None


def check_release_age(
    package_name: str,
    version: str,
    threshold_days: float = DEFAULT_STALENESS_THRESHOLD_DAYS,
    timeout: float = _PYPI_TIMEOUT,
) -> List[Finding]:
    """Check if a release has files uploaded with suspicious time spread.

    Returns a list of findings (0 or 1 element). Returns empty list on
    network error or if the release timing looks normal.
    """
    info = query_release_age(package_name, version, timeout=timeout)
    if info is None:
        return []

    if info.file_count < 2:
        # Single file — nothing to compare
        return []

    span = info.upload_span_days
    if span <= threshold_days:
        return []

    return [Finding(
        level=RiskLevel.LOW,
        file_path=f"{package_name}=={version}",
        line=0,
        description=(
            f"Release has files uploaded {span:.1f} days apart "
            f"({info.file_count} files) — possible late file injection "
            f"within PyPI's 14-day upload window"
        ),
    )]
