"""
Tests for pipguard.aggregator — allowlist logic and risk aggregation.

Critical: CRITICAL findings are NEVER reduced by the allowlist (Amendment A3).
"""

import os
import sys
import pytest

sys.path.insert(0, os.path.join(os.path.dirname(__file__), ".."))

from pipguard.aggregator import (
    aggregate_findings,
    check_package_name_for_homoglyph,
    is_allowlisted,
    normalize_package_name,
    print_findings_report,
    SEED_ALLOWLIST,
)
from pipguard.models import Finding, PackageScanResult, RiskLevel


def _finding(level: RiskLevel) -> Finding:
    return Finding(level=level, file_path="setup.py", line=1, description="test")


class TestNormalizePackageName:
    def test_lowercase(self):
        assert normalize_package_name("Requests") == "requests"

    def test_underscores_to_hyphens(self):
        assert normalize_package_name("google_auth") == "google-auth"

    def test_already_normalized(self):
        assert normalize_package_name("boto3") == "boto3"


class TestIsAllowlisted:
    def test_seed_allowlist_packages_are_allowlisted(self):
        for pkg in SEED_ALLOWLIST:
            assert is_allowlisted(pkg), f"{pkg} should be allowlisted"

    def test_unknown_package_not_allowlisted(self):
        assert not is_allowlisted("litellm")
        assert not is_allowlisted("requests")
        assert not is_allowlisted("numpy")

    def test_extra_allow_extends_allowlist(self):
        assert is_allowlisted("my-corp-sdk", extra_allow=["my-corp-sdk"])

    def test_extra_allow_case_insensitive(self):
        assert is_allowlisted("My-Corp-SDK", extra_allow=["my-corp-sdk"])

    def test_allowlist_is_exact_match_not_prefix(self):
        """'google-cloud-exfil' must NOT match just because 'google-cloud-storage' is listed."""
        assert not is_allowlisted("google-cloud-exfil")
        assert not is_allowlisted("boto3-evil")
        assert not is_allowlisted("botocore-malicious")

    def test_typosquatting_not_allowlisted(self):
        """Typosquatted names are not allowlisted."""
        assert not is_allowlisted("b0to3")
        assert not is_allowlisted("botoO3")


class TestAggregateFindingsAllowlist:
    """Amendment A3: allowlist reduces HIGH → MEDIUM, CRITICAL is NEVER reduced."""

    def test_critical_not_reduced_for_allowlisted_package(self):
        """CRITICAL finding on keyring must remain CRITICAL."""
        result = aggregate_findings(
            "keyring", [_finding(RiskLevel.CRITICAL)]
        )
        assert result.is_allowlisted is True
        assert result.effective_level == RiskLevel.CRITICAL, (
            "CRITICAL must never be reduced by the allowlist"
        )

    def test_high_reduced_to_medium_for_allowlisted(self):
        """HIGH finding on boto3 (allowlisted) → effective MEDIUM."""
        result = aggregate_findings(
            "boto3", [_finding(RiskLevel.HIGH)]
        )
        assert result.is_allowlisted is True
        assert result.max_level == RiskLevel.HIGH
        assert result.effective_level == RiskLevel.MEDIUM

    def test_high_not_reduced_for_non_allowlisted(self):
        result = aggregate_findings(
            "evil-pkg", [_finding(RiskLevel.HIGH)]
        )
        assert result.is_allowlisted is False
        assert result.effective_level == RiskLevel.HIGH

    def test_medium_unchanged_for_allowlisted(self):
        result = aggregate_findings(
            "keyring", [_finding(RiskLevel.MEDIUM)]
        )
        assert result.effective_level == RiskLevel.MEDIUM

    def test_clean_package(self):
        result = aggregate_findings("numpy", [])
        assert result.effective_level == RiskLevel.CLEAN
        assert result.is_allowlisted is False

    def test_binary_only_flag(self):
        result = aggregate_findings("mypkg", [], is_binary_only=True)
        assert result.is_binary_only is True
        # TODO-5: binary-only packages are MEDIUM — confirmation gate fires
        assert result.effective_level == RiskLevel.MEDIUM

    def test_extra_allow_reduces_high_to_medium(self):
        result = aggregate_findings(
            "my-corp-sdk",
            [_finding(RiskLevel.HIGH)],
            extra_allow=["my-corp-sdk"],
        )
        assert result.effective_level == RiskLevel.MEDIUM

    def test_extra_allow_does_not_reduce_critical(self):
        result = aggregate_findings(
            "my-corp-sdk",
            [_finding(RiskLevel.CRITICAL)],
            extra_allow=["my-corp-sdk"],
        )
        assert result.effective_level == RiskLevel.CRITICAL


class TestPackageScanResultMaxLevel:
    def test_max_level_with_multiple_findings(self):
        findings = [
            _finding(RiskLevel.LOW),
            _finding(RiskLevel.HIGH),
            _finding(RiskLevel.MEDIUM),
        ]
        result = PackageScanResult("pkg", "", findings=findings)
        assert result.max_level == RiskLevel.HIGH

    def test_max_level_empty_is_clean(self):
        result = PackageScanResult("pkg", "", findings=[])
        assert result.max_level == RiskLevel.CLEAN


class TestCheckPackageNameForHomoglyph:
    """TODO-2: Non-ASCII package names are flagged as possible homoglyph attacks."""

    def test_ascii_name_returns_none(self):
        assert check_package_name_for_homoglyph("boto3") is None
        assert check_package_name_for_homoglyph("requests") is None
        assert check_package_name_for_homoglyph("my-corp-sdk") is None

    def test_cyrillic_o_in_name_is_high(self):
        """'bоto3' with Cyrillic 'о' (U+043E) must produce a HIGH finding."""
        finding = check_package_name_for_homoglyph("b\u043eto3")  # Cyrillic о
        assert finding is not None
        assert finding.level == RiskLevel.HIGH
        assert "U+043E" in finding.description or "043E" in finding.description.upper()

    def test_non_ascii_name_description_mentions_homoglyph(self):
        finding = check_package_name_for_homoglyph("requ\u00e9sts")  # é
        assert finding is not None
        assert "homoglyph" in finding.description.lower() or "typosquat" in finding.description.lower()

    def test_normalized_name_used_for_allowlist(self):
        """NFKC-normalized homoglyph name must NOT match boto3 allowlist entry."""
        # 'bоto3' with Cyrillic о normalizes differently than 'boto3'
        assert not is_allowlisted("b\u043eto3")


class TestNormalizePackageNameNFKC:
    """TODO-2: NFKC normalization in normalize_package_name."""

    def test_nfkc_fullwidth_digit(self):
        """Fullwidth digit U+FF11 ('１') normalises to ASCII '1'."""
        assert normalize_package_name("boto\uff113") == "boto13"

    def test_ascii_unchanged(self):
        assert normalize_package_name("Requests") == "requests"
        assert normalize_package_name("google_auth") == "google-auth"


class TestPrintFindingsReport:
    def test_default_report_collapses_low_and_hides_clean_details(self, capsys):
        low = PackageScanResult(
            "zipp",
            "",
            findings=[Finding(level=RiskLevel.LOW, file_path="zipp/mod.py", line=7, description="dyn import")],
        )
        clean = PackageScanResult("attrs", "", findings=[])
        print_findings_report([clean, low])
        out = capsys.readouterr().out
        assert "Scan summary:" in out
        assert "[LOW] zipp" in out
        assert "zipp/mod.py" not in out
        assert "attrs — CLEAN" not in out

    def test_verbose_report_shows_low_and_clean_details(self, capsys):
        low = PackageScanResult(
            "zipp",
            "",
            findings=[Finding(level=RiskLevel.LOW, file_path="zipp/mod.py", line=7, description="dyn import")],
        )
        clean = PackageScanResult("attrs", "", findings=[])
        print_findings_report([clean, low], verbose=True)
        out = capsys.readouterr().out
        assert "zipp/mod.py:7" in out
        assert "attrs — CLEAN" in out

    def test_report_order_is_deterministic(self, capsys):
        critical = PackageScanResult(
            "omega",
            "",
            findings=[Finding(level=RiskLevel.CRITICAL, file_path="omega/setup.py", line=1, description="boom")],
        )
        medium = PackageScanResult(
            "beta",
            "",
            findings=[Finding(level=RiskLevel.MEDIUM, file_path="beta/net.py", line=3, description="net")],
        )
        low_a = PackageScanResult(
            "aardvark",
            "",
            findings=[Finding(level=RiskLevel.LOW, file_path="aardvark/mod.py", line=4, description="dyn")],
        )
        low_z = PackageScanResult(
            "zeta",
            "",
            findings=[Finding(level=RiskLevel.LOW, file_path="zeta/mod.py", line=5, description="dyn")],
        )
        print_findings_report([low_z, medium, low_a, critical])
        out = capsys.readouterr().out
        assert out.index("CRITICAL") < out.index("MEDIUM") < out.index("LOW")
        assert out.index("aardvark") < out.index("zeta")

    def test_findings_sorted_by_level_then_location(self, capsys):
        result = PackageScanResult(
            "pkg",
            "",
            findings=[
                Finding(level=RiskLevel.LOW, file_path="z.py", line=4, description="z"),
                Finding(level=RiskLevel.MEDIUM, file_path="b.py", line=2, description="m"),
                Finding(level=RiskLevel.LOW, file_path="a.py", line=1, description="a"),
            ],
        )
        print_findings_report([result], verbose=True)
        out = capsys.readouterr().out
        assert out.index("b.py:2") < out.index("a.py:1") < out.index("z.py:4")
