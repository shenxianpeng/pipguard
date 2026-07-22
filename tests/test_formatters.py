"""Tests for pipguard.formatters — JSON and SARIF output."""

import json

from pipguard.formatters import format_json, format_sarif
from pipguard.models import Finding, PackageScanResult, RiskLevel


def _make_result(
    name="test-pkg",
    version="1.0.0",
    findings=None,
    is_allowlisted=False,
    is_binary_only=False,
):
    return PackageScanResult(
        package_name=name,
        version=version,
        findings=findings or [],
        is_allowlisted=is_allowlisted,
        is_binary_only=is_binary_only,
    )


class TestFormatJson:
    def test_empty_results(self):
        output = format_json([])
        data = json.loads(output)
        assert data["schema_version"] == "1.0"
        assert data["tool"] == "pipguard"
        assert data["results"] == []
        assert data["summary"]["total_packages"] == 0

    def test_clean_package(self):
        result = _make_result()
        output = format_json([result])
        data = json.loads(output)
        assert len(data["results"]) == 1
        assert data["results"][0]["package_name"] == "test-pkg"
        assert data["results"][0]["effective_level"] == "CLEAN"
        assert data["summary"]["by_level"]["CLEAN"] == 1

    def test_package_with_findings(self):
        findings = [
            Finding(
                level=RiskLevel.HIGH,
                file_path="setup.py",
                line=10,
                description="Network call in install hook",
                snippet="requests.get('http://evil.com')",
            ),
            Finding(
                level=RiskLevel.MEDIUM,
                file_path="pkg/main.py",
                line=25,
                description="Sensitive env var access",
            ),
        ]
        result = _make_result(findings=findings)
        output = format_json([result])
        data = json.loads(output)
        assert data["results"][0]["max_level"] == "HIGH"
        assert len(data["results"][0]["findings"]) == 2
        assert data["results"][0]["findings"][0]["snippet"] == "requests.get('http://evil.com')"
        assert data["summary"]["by_level"]["HIGH"] == 1

    def test_multiple_packages(self):
        results = [
            _make_result(name="clean-pkg"),
            _make_result(
                name="risky-pkg",
                findings=[
                    Finding(RiskLevel.CRITICAL, "setup.py", 1, "eval/exec with base64"),
                ],
            ),
        ]
        output = format_json(results)
        data = json.loads(output)
        assert data["summary"]["total_packages"] == 2
        assert data["summary"]["by_level"]["CLEAN"] == 1
        assert data["summary"]["by_level"]["CRITICAL"] == 1

    def test_allowlisted_package(self):
        result = _make_result(
            is_allowlisted=True,
            findings=[Finding(RiskLevel.HIGH, "pkg.py", 5, "cred access")],
        )
        output = format_json([result])
        data = json.loads(output)
        # Allowlisted HIGH → effective MEDIUM
        assert data["results"][0]["effective_level"] == "MEDIUM"
        assert data["results"][0]["is_allowlisted"] is True

    def test_binary_only_package(self):
        result = _make_result(is_binary_only=True)
        output = format_json([result])
        data = json.loads(output)
        assert data["results"][0]["is_binary_only"] is True
        # Binary-only with no findings → effective MEDIUM
        assert data["results"][0]["effective_level"] == "MEDIUM"

    def test_json_is_valid(self):
        """Ensure output is always valid JSON."""
        results = [
            _make_result(name="pkg-with-'quotes'"),
            _make_result(
                name="unicode-pkg",
                findings=[Finding(RiskLevel.LOW, "f.py", 1, "desc with émojis 🔍")],
            ),
        ]
        output = format_json(results)
        # Should not raise
        data = json.loads(output)
        assert data["tool"] == "pipguard"


class TestFormatSarif:
    def test_empty_results(self):
        output = format_sarif([])
        data = json.loads(output)
        assert data["version"] == "2.1.0"
        assert data["$schema"].endswith("sarif-schema-2.1.0.json")
        assert len(data["runs"]) == 1
        assert data["runs"][0]["results"] == []

    def test_sarif_structure(self):
        findings = [
            Finding(RiskLevel.CRITICAL, "setup.py", 5, "eval/exec on base64 payload"),
        ]
        result = _make_result(findings=findings)
        output = format_sarif([result])
        data = json.loads(output)

        run = data["runs"][0]
        assert run["tool"]["driver"]["name"] == "pipguard"
        assert len(run["tool"]["driver"]["rules"]) == 1
        assert len(run["results"]) == 1

        sarif_result = run["results"][0]
        assert sarif_result["level"] == "error"
        assert "test-pkg" in sarif_result["message"]["text"]
        assert sarif_result["locations"][0]["physicalLocation"]["region"]["startLine"] == 5

    def test_sarif_rule_deduplication(self):
        """Same description pattern should produce one rule with multiple results."""
        findings = [
            Finding(RiskLevel.HIGH, "a.py", 1, "Network call: requests.get"),
            Finding(RiskLevel.HIGH, "b.py", 10, "Network call: urllib.request.urlopen"),
        ]
        result = _make_result(findings=findings)
        output = format_sarif([result])
        data = json.loads(output)

        run = data["runs"][0]
        # Both findings map to the same rule category
        assert len(run["results"]) == 2
        # Rules should be deduplicated
        assert len(run["tool"]["driver"]["rules"]) <= 2

    def test_sarif_severity_mapping(self):
        levels = [
            (RiskLevel.CRITICAL, "error"),
            (RiskLevel.HIGH, "error"),
            (RiskLevel.MEDIUM, "warning"),
            (RiskLevel.LOW, "note"),
        ]
        for risk_level, expected_sarif_level in levels:
            result = _make_result(
                findings=[Finding(risk_level, "f.py", 1, "test finding")],
            )
            output = format_sarif([result])
            data = json.loads(output)
            assert data["runs"][0]["results"][0]["level"] == expected_sarif_level

    def test_sarif_valid_json(self):
        results = [
            _make_result(
                findings=[
                    Finding(RiskLevel.HIGH, "setup.py", 1, "shell exec"),
                    Finding(RiskLevel.MEDIUM, "pkg/net.py", 42, "socket.connect call"),
                ],
            ),
        ]
        output = format_sarif(results)
        data = json.loads(output)
        assert data["version"] == "2.1.0"
