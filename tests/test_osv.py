"""Tests for pipguard.osv — osv.dev API integration."""

import json
from unittest.mock import MagicMock, patch

from pipguard.osv import OsvVulnerability, _parse_osv_response, query_osv


class TestOsvVulnerability:
    def test_short_id_prefers_cve_alias(self):
        vuln = OsvVulnerability(
            vuln_id="GHSA-1234-abcd",
            aliases=["CVE-2024-1234"],
        )
        assert vuln.short_id == "CVE-2024-1234"

    def test_short_id_falls_back_to_vuln_id(self):
        vuln = OsvVulnerability(vuln_id="PYSEC-2024-1")
        assert vuln.short_id == "PYSEC-2024-1"

    def test_short_id_skips_non_cve_aliases(self):
        vuln = OsvVulnerability(
            vuln_id="GHSA-abcd",
            aliases=["GHSA-abcd", "CVE-2024-9999"],
        )
        assert vuln.short_id == "CVE-2024-9999"

    def test_one_line_basic(self):
        vuln = OsvVulnerability(
            vuln_id="GHSA-1234",
            summary="Cross-site scripting vulnerability",
            severity="HIGH",
            fixed_version="2.0.0",
        )
        line = vuln.one_line
        assert "GHSA-1234" in line
        assert "[HIGH]" in line
        assert "Cross-site scripting" in line
        assert "(fixed in 2.0.0)" in line

    def test_one_line_long_summary_truncated(self):
        vuln = OsvVulnerability(
            vuln_id="CVE-2024-1",
            summary="A" * 200,
            severity="LOW",
        )
        line = vuln.one_line
        assert len(line) < 250
        assert "..." in line

    def test_one_line_no_severity(self):
        vuln = OsvVulnerability(vuln_id="GHSA-99", summary="Test")
        assert "[None]" not in vuln.one_line

    def test_one_line_without_summary(self):
        """one_line should not include the summary if it's empty."""
        vuln = OsvVulnerability(vuln_id="CVE-2024-1", summary="")
        line = vuln.one_line
        assert "CVE-2024-1" in line
        # No summary text appended
        assert line.strip().endswith("CVE-2024-1") or line == "CVE-2024-1"

    def test_one_line_without_fixed_version(self):
        """one_line should not include 'fixed in' when fixed_version is None."""
        vuln = OsvVulnerability(vuln_id="GHSA-99", summary="Test", fixed_version=None)
        assert "fixed in" not in vuln.one_line


# ── OSV API response parsing ────────────────────────────────────────────────

class TestParseOsvResponse:
    """Test parsing various osv.dev API response shapes."""

    def test_empty_response(self):
        assert _parse_osv_response({}) == []

    def test_no_vulns(self):
        assert _parse_osv_response({"vulns": []}) == []

    def test_single_vuln_basic(self):
        data = {
            "vulns": [{
                "id": "GHSA-1234-abcd",
                "summary": "Remote code execution in Jinja2",
                "aliases": ["CVE-2024-12345"],
            }]
        }
        vulns = _parse_osv_response(data)
        assert len(vulns) == 1
        assert vulns[0].vuln_id == "GHSA-1234-abcd"
        assert vulns[0].summary == "Remote code execution in Jinja2"
        assert "CVE-2024-12345" in vulns[0].aliases
        assert vulns[0].short_id == "CVE-2024-12345"

    def test_vuln_with_fixed_version(self):
        data = {
            "vulns": [{
                "id": "GHSA-xxxx",
                "summary": "SQL injection",
                "affected": [{
                    "ranges": [{
                        "type": "ECOSYSTEM",
                        "events": [
                            {"introduced": "0"},
                            {"fixed": "1.5.0"},
                        ],
                    }],
                }],
            }]
        }
        vulns = _parse_osv_response(data)
        assert len(vulns) == 1
        assert vulns[0].fixed_version == "1.5.0"

    def test_vuln_with_database_specific_severity(self):
        data = {
            "vulns": [{
                "id": "GHSA-yyyy",
                "summary": "Test",
                "database_specific": {"severity": "CRITICAL"},
            }]
        }
        vulns = _parse_osv_response(data)
        assert len(vulns) == 1
        assert vulns[0].severity == "CRITICAL"

    def test_multiple_vulns(self):
        data = {
            "vulns": [
                {"id": "GHSA-1", "summary": "First"},
                {"id": "GHSA-2", "summary": "Second", "aliases": ["CVE-2024-2"]},
            ]
        }
        vulns = _parse_osv_response(data)
        assert len(vulns) == 2
        assert vulns[0].vuln_id == "GHSA-1"
        assert vulns[1].vuln_id == "GHSA-2"

    def test_entry_without_id_skipped(self):
        data = {
            "vulns": [
                {"summary": "No ID here"},
                {"id": "GHSA-valid", "summary": "Valid"},
            ]
        }
        vulns = _parse_osv_response(data)
        assert len(vulns) == 1
        assert vulns[0].vuln_id == "GHSA-valid"

    def test_vulns_field_is_none(self):
        data = {"vulns": None}
        assert _parse_osv_response(data) == []

    def test_database_specific_not_a_dict(self):
        """database_specific that is not a dict should not crash."""
        data = {
            "vulns": [{
                "id": "GHSA-zzzz",
                "summary": "Test",
                "database_specific": "not-a-dict",
            }]
        }
        vulns = _parse_osv_response(data)
        assert len(vulns) == 1
        assert vulns[0].severity is None

    def test_summary_from_database_specific_when_entry_summary_empty(self):
        """When entry has no summary, fall back to database_specific summary."""
        data = {
            "vulns": [{
                "id": "GHSA-dbonly",
                "database_specific": {"summary": "From database_specific"},
            }]
        }
        vulns = _parse_osv_response(data)
        assert len(vulns) == 1
        assert vulns[0].summary == "From database_specific"

    def test_affected_ranges_non_ecosystem_type(self):
        """Ranges with type != ECOSYSTEM should not extract fixed version."""
        data = {
            "vulns": [{
                "id": "GHSA-semver",
                "summary": "Test",
                "affected": [{
                    "ranges": [{
                        "type": "SEMVER",
                        "events": [
                            {"introduced": "0"},
                            {"fixed": "9.9.9"},
                        ],
                    }],
                }],
            }]
        }
        vulns = _parse_osv_response(data)
        assert len(vulns) == 1
        assert vulns[0].fixed_version is None

    def test_affected_ranges_empty_events(self):
        """ECOSYSTEM range with empty events list should not crash."""
        data = {
            "vulns": [{
                "id": "GHSA-no-events",
                "summary": "Test",
                "affected": [{
                    "ranges": [{
                        "type": "ECOSYSTEM",
                        "events": [],
                    }],
                }],
            }]
        }
        vulns = _parse_osv_response(data)
        assert len(vulns) == 1
        assert vulns[0].fixed_version is None

    def test_affected_empty_ranges(self):
        """Affected entry with empty ranges list should not crash."""
        data = {
            "vulns": [{
                "id": "GHSA-no-ranges",
                "summary": "Test",
                "affected": [{"ranges": []}],
            }]
        }
        vulns = _parse_osv_response(data)
        assert len(vulns) == 1
        assert vulns[0].fixed_version is None

    def test_events_without_fixed_key(self):
        """Events list where no event has a 'fixed' key."""
        data = {
            "vulns": [{
                "id": "GHSA-no-fix",
                "summary": "Test",
                "affected": [{
                    "ranges": [{
                        "type": "ECOSYSTEM",
                        "events": [
                            {"introduced": "0"},
                            {"last_affected": "1.0.0"},
                        ],
                    }],
                }],
            }]
        }
        vulns = _parse_osv_response(data)
        assert len(vulns) == 1
        assert vulns[0].fixed_version is None


# ── query_osv integration tests ─────────────────────────────────────────────

class TestQueryOsv:
    """Test the full query_osv function with mocked HTTP."""

    def test_query_returns_vulns(self):
        response_data = json.dumps({
            "vulns": [{
                "id": "GHSA-abc",
                "summary": "Test vuln",
                "aliases": ["CVE-2024-9999"],
            }]
        }).encode("utf-8")

        mock_resp = MagicMock()
        mock_resp.__enter__.return_value = mock_resp
        mock_resp.read.return_value = response_data

        with patch("urllib.request.urlopen", return_value=mock_resp) as mock_open:
            vulns = query_osv("jinja2", "2.4.1")
            assert len(vulns) == 1
            assert vulns[0].vuln_id == "GHSA-abc"

            # Verify the request body
            call_args = mock_open.call_args[0][0]
            sent_data = json.loads(call_args.data.decode("utf-8"))
            assert sent_data["package"]["name"] == "jinja2"
            assert sent_data["package"]["ecosystem"] == "PyPI"
            assert sent_data["version"] == "2.4.1"

    def test_query_no_vulns_found(self):
        response_data = json.dumps({}).encode("utf-8")
        mock_resp = MagicMock()
        mock_resp.__enter__.return_value = mock_resp
        mock_resp.read.return_value = response_data

        with patch("urllib.request.urlopen", return_value=mock_resp):
            assert query_osv("clean-pkg", "1.0.0") == []

    def test_query_http_error_returns_empty(self):
        with patch("urllib.request.urlopen", side_effect=OSError("network down")):
            assert query_osv("pkg", "1.0") == []

    def test_query_timeout_returns_empty(self):
        import socket
        with patch("urllib.request.urlopen", side_effect=socket.timeout("timed out")):
            assert query_osv("pkg", "1.0") == []

    def test_query_invalid_json_returns_empty(self):
        mock_resp = MagicMock()
        mock_resp.__enter__.return_value = mock_resp
        mock_resp.read.return_value = b"not valid json {{{"

        with patch("urllib.request.urlopen", return_value=mock_resp):
            assert query_osv("pkg", "1.0") == []

    def test_query_empty_version_returns_empty(self):
        """No API call should be made when version is empty string."""
        assert query_osv("pkg", "") == []
