"""Tests for pipguard.release_age module."""

from datetime import datetime, timezone

from pipguard.models import RiskLevel
from pipguard.release_age import (
    DEFAULT_STALENESS_THRESHOLD_DAYS,
    ReleaseAgeInfo,
    _parse_release_timestamps,
    _parse_timestamp,
    check_release_age,
    query_release_age,
)


class TestParseTimestamp:
    def test_iso8601_with_z(self):
        dt = _parse_timestamp("2026-07-01T12:00:00Z")
        assert dt == datetime(2026, 7, 1, 12, 0, 0, tzinfo=timezone.utc)

    def test_iso8601_with_offset(self):
        dt = _parse_timestamp("2026-07-01T12:00:00+00:00")
        assert dt == datetime(2026, 7, 1, 12, 0, 0, tzinfo=timezone.utc)

    def test_bare_datetime(self):
        dt = _parse_timestamp("2026-07-01T12:00:00")
        assert dt == datetime(2026, 7, 1, 12, 0, 0, tzinfo=timezone.utc)

    def test_invalid(self):
        assert _parse_timestamp("not-a-date") is None


class TestReleaseAgeInfo:
    def test_span_days(self):
        info = ReleaseAgeInfo(
            oldest_upload=datetime(2026, 7, 1, 0, 0, 0, tzinfo=timezone.utc),
            newest_upload=datetime(2026, 7, 5, 0, 0, 0, tzinfo=timezone.utc),
            file_count=3,
        )
        assert info.upload_span_days == 4.0

    def test_span_days_none(self):
        info = ReleaseAgeInfo()
        assert info.upload_span_days == 0.0


class TestParseReleaseTimestamps:
    def test_normal_response(self):
        data = {
            "urls": [
                {"upload_time_iso_8601": "2026-07-01T10:00:00Z"},
                {"upload_time_iso_8601": "2026-07-01T12:00:00Z"},
                {"upload_time_iso_8601": "2026-07-05T08:00:00Z"},
            ]
        }
        info = _parse_release_timestamps(data)
        assert info is not None
        assert info.file_count == 3
        assert info.oldest_upload == datetime(2026, 7, 1, 10, 0, 0, tzinfo=timezone.utc)
        assert info.newest_upload == datetime(2026, 7, 5, 8, 0, 0, tzinfo=timezone.utc)
        assert 3.9 < info.upload_span_days < 4.0

    def test_empty_urls(self):
        assert _parse_release_timestamps({"urls": []}) is None

    def test_no_urls_key(self):
        assert _parse_release_timestamps({}) is None

    def test_fallback_upload_time(self):
        data = {
            "urls": [
                {"upload_time": "2026-07-01T10:00:00"},
                {"upload_time": "2026-07-02T10:00:00"},
            ]
        }
        info = _parse_release_timestamps(data)
        assert info is not None
        assert info.file_count == 2
        assert info.upload_span_days == 1.0


class TestCheckReleaseAge:
    def test_returns_empty_for_no_version(self):
        # query_release_age returns None for empty version → no findings
        findings = check_release_age("requests", "")
        assert findings == []

    def test_returns_empty_on_network_error(self, monkeypatch):
        """Network errors should return empty list (graceful degradation)."""
        def mock_query(*args, **kwargs):
            return None

        monkeypatch.setattr("pipguard.release_age.query_release_age", mock_query)
        findings = check_release_age("requests", "2.28.0")
        assert findings == []

    def test_flags_large_span(self, monkeypatch):
        """A release with files uploaded far apart should produce a finding."""
        info = ReleaseAgeInfo(
            oldest_upload=datetime(2026, 7, 1, 0, 0, 0, tzinfo=timezone.utc),
            newest_upload=datetime(2026, 7, 10, 0, 0, 0, tzinfo=timezone.utc),
            file_count=4,
        )
        monkeypatch.setattr("pipguard.release_age.query_release_age", lambda *a, **kw: info)
        findings = check_release_age("some-pkg", "1.0.0")
        assert len(findings) == 1
        assert findings[0].level == RiskLevel.LOW
        assert "9.0 days apart" in findings[0].description
        assert "late file injection" in findings[0].description

    def test_no_finding_below_threshold(self, monkeypatch):
        """Files uploaded within the threshold should not produce findings."""
        info = ReleaseAgeInfo(
            oldest_upload=datetime(2026, 7, 1, 0, 0, 0, tzinfo=timezone.utc),
            newest_upload=datetime(2026, 7, 2, 0, 0, 0, tzinfo=timezone.utc),
            file_count=3,
        )
        monkeypatch.setattr("pipguard.release_age.query_release_age", lambda *a, **kw: info)
        findings = check_release_age("some-pkg", "1.0.0")
        assert findings == []

    def test_single_file_no_finding(self, monkeypatch):
        """A release with only one file should not trigger."""
        info = ReleaseAgeInfo(
            oldest_upload=datetime(2026, 7, 1, 0, 0, 0, tzinfo=timezone.utc),
            newest_upload=datetime(2026, 7, 1, 0, 0, 0, tzinfo=timezone.utc),
            file_count=1,
        )
        monkeypatch.setattr("pipguard.release_age.query_release_age", lambda *a, **kw: info)
        findings = check_release_age("some-pkg", "1.0.0")
        assert findings == []
