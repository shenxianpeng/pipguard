"""
Tests for pipguard.cli — argument parsing, requirements validation,
package name extraction, and gate logic.

Network-dependent tests (actual pip download) are gated by the
PIPGUARD_NETWORK_TESTS environment variable.
"""

import os
import sys
import tempfile
import types
from unittest.mock import MagicMock, patch

import pytest

sys.path.insert(0, os.path.join(os.path.dirname(__file__), ".."))

from pipguard.cli import (
    _pkg_name_from_filename,
    _pkg_version_from_filename,
    _validate_requirements_file,
    build_parser,
    cmd_install,
    cmd_scan_feed,
)
from pipguard.models import Finding, PackageScanResult, RiskLevel

_FEED_XML = (
    '<rss><channel>'
    '<item><title>evilpkg 1.2.3</title>'
    '<link>https://pypi.org/project/evilpkg/1.2.3/</link></item>'
    '</channel></rss>'
)


# ── Package name extraction ──────────────────────────────────────────────────

class TestPkgNameFromFilename:
    def test_simple_wheel(self):
        assert _pkg_name_from_filename("requests-2.28.0-py3-none-any.whl") == "requests"

    def test_hyphenated_wheel(self):
        assert _pkg_name_from_filename(
            "google_cloud_storage-2.10.0-py2.py3-none-any.whl"
        ) == "google_cloud_storage"

    def test_sdist_tar_gz(self):
        assert _pkg_name_from_filename("litellm-1.82.8.tar.gz") == "litellm"

    def test_sdist_zip(self):
        assert _pkg_name_from_filename("mypackage-0.1.0.zip") == "mypackage"

    def test_multipart_name_wheel(self):
        result = _pkg_name_from_filename(
            "google-cloud-bigquery-3.11.0-py2.py3-none-any.whl"
        )
        assert result == "google-cloud-bigquery"

    def test_path_prefix_stripped(self):
        result = _pkg_name_from_filename("/tmp/pipguard-xxxx/requests-2.28.0-py3-none-any.whl")
        assert result == "requests"

    def test_version_extracted_from_wheel(self):
        assert _pkg_version_from_filename("requests-2.28.0-py3-none-any.whl") == "2.28.0"


# ── requirements.txt validation ──────────────────────────────────────────────

class TestValidateRequirementsFile:

    def _write(self, tmp_path, content):
        req = tmp_path / "requirements.txt"
        req.write_text(content)
        return str(req)

    def test_valid_pinned_deps_returns_0(self, tmp_path):
        f = self._write(tmp_path, "requests==2.28.0\nnumpy>=1.24\n")
        assert _validate_requirements_file(f) == 0

    def test_vcs_dep_returns_2(self, tmp_path):
        f = self._write(tmp_path, "git+https://github.com/org/repo.git@main\n")
        assert _validate_requirements_file(f) == 2

    def test_vcs_pinned_commit_returns_0(self, tmp_path):
        f = self._write(tmp_path, "git+https://github.com/org/repo.git@a1b2c3d4\n")
        assert _validate_requirements_file(f) == 0

    def test_pep508_direct_url_with_hash_returns_0(self, tmp_path):
        f = self._write(
            tmp_path,
            "pkg @ https://example.com/pkg-1.0.0.whl#sha256=abcdefabcdefabcdefabcdefabcdefab\n",
        )
        assert _validate_requirements_file(f) == 0

    def test_local_path_dep_returns_2(self, tmp_path):
        f = self._write(tmp_path, "./my-local-package\n")
        assert _validate_requirements_file(f) == 2

    def test_absolute_local_path_returns_2(self, tmp_path):
        f = self._write(tmp_path, "/home/user/my-pkg\n")
        assert _validate_requirements_file(f) == 2

    def test_editable_install_is_skipped_not_rejected(self, tmp_path, capsys):
        """Editable installs produce a warning but return 0."""
        f = self._write(tmp_path, "-e .\n")
        assert _validate_requirements_file(f) == 0

    def test_hash_locked_deps_are_valid(self, tmp_path):
        f = self._write(
            tmp_path,
            "requests==2.28.0 \\\n"
            "    --hash=sha256:abcdef1234567890abcdef1234567890abcdef1234567890abcdef1234567890\n",
        )
        assert _validate_requirements_file(f) == 0

    def test_blank_and_comments_are_valid(self, tmp_path):
        f = self._write(tmp_path, "# comment\n\n# another\n")
        assert _validate_requirements_file(f) == 0

    def test_missing_file_returns_2(self, tmp_path):
        assert _validate_requirements_file(str(tmp_path / "nonexistent.txt")) == 2

    def test_multiple_vcs_deps_returns_2(self, tmp_path):
        f = self._write(
            tmp_path,
            "requests==2.28.0\n"
            "git+https://github.com/org/repo.git\n"
            "hg+https://bitbucket.org/org/repo\n",
        )
        assert _validate_requirements_file(f) == 2

    def test_require_hashes_rejects_unhashed_entry(self, tmp_path):
        f = self._write(tmp_path, "requests==2.28.0\n")
        assert _validate_requirements_file(f, require_hashes=True) == 2

    def test_require_hashes_accepts_hashed_entry(self, tmp_path):
        f = self._write(
            tmp_path,
            "requests==2.28.0 --hash=sha256:abcdef1234567890abcdef1234567890abcdef1234567890abcdef1234567890\n",
        )
        assert _validate_requirements_file(f, require_hashes=True) == 0


# ── CLI parser ───────────────────────────────────────────────────────────────

class TestBuildParser:
    def test_install_parses_package(self):
        parser = build_parser()
        args = parser.parse_args(["install", "requests"])
        assert args.command == "install"
        assert args.packages == ["requests"]

    def test_install_parses_multiple_packages(self):
        parser = build_parser()
        args = parser.parse_args(["install", "requests", "numpy"])
        assert args.packages == ["requests", "numpy"]

    def test_install_parses_requirements_file(self):
        parser = build_parser()
        args = parser.parse_args(["install", "-r", "requirements.txt"])
        assert getattr(args, "r") == "requirements.txt"

    def test_yes_flag(self):
        parser = build_parser()
        args = parser.parse_args(["install", "--yes", "requests"])
        assert args.yes is True

    def test_short_yes_flag(self):
        parser = build_parser()
        args = parser.parse_args(["install", "-y", "requests"])
        assert args.yes is True

    def test_force_flag(self):
        parser = build_parser()
        args = parser.parse_args(["install", "--force", "requests"])
        assert args.force is True

    def test_allow_flag(self):
        parser = build_parser()
        args = parser.parse_args(["install", "--allow", "boto3", "requests"])
        assert "boto3" in args.allow

    def test_allow_sdist_flag(self):
        parser = build_parser()
        args = parser.parse_args(["install", "--allow-sdist", "requests"])
        assert args.allow_sdist is True

    def test_require_hashes_flag(self):
        parser = build_parser()
        args = parser.parse_args(["install", "--require-hashes", "requests"])
        assert args.require_hashes is True

    def test_verbose_flag(self):
        parser = build_parser()
        args = parser.parse_args(["install", "--verbose", "requests"])
        assert args.verbose is True

    def test_show_pip_output_flag(self):
        parser = build_parser()
        args = parser.parse_args(["install", "--show-pip-output", "requests"])
        assert args.show_pip_output is True

    def test_sandbox_flag(self):
        parser = build_parser()
        args = parser.parse_args(["install", "--sandbox", "requests"])
        assert args.sandbox is True

    def test_policy_flag(self):
        parser = build_parser()
        args = parser.parse_args(["install", "--policy", "pipguard.toml", "requests"])
        assert args.policy == "pipguard.toml"

    def test_intel_flags(self):
        parser = build_parser()
        args = parser.parse_args(["install", "--intel-feed", "feed.json", "--enforce-intel", "requests"])
        assert args.intel_feed == "feed.json"
        assert args.enforce_intel is True

    def test_version_flag(self, capsys):
        parser = build_parser()
        with pytest.raises(SystemExit) as exc:
            parser.parse_args(["--version"])
        assert exc.value.code == 0

    def test_no_args_exits(self, capsys):
        parser = build_parser()
        with pytest.raises(SystemExit):
            parser.parse_args([])


# ── cmd_install gate logic (mock download/scan/install) ──────────────────────

def _make_args(**kwargs):
    """Build a minimal args namespace for cmd_install."""
    defaults = dict(
        packages=["requests"],
        r=None,
        yes=False,
        force=False,
        allow=[],
        allow_sdist=False,
        require_hashes=False,
        verbose=False,
        show_pip_output=False,
        policy=None,
        intel_feed=None,
        enforce_intel=False,
    )
    defaults.update(kwargs)
    return types.SimpleNamespace(**defaults)


def _make_scan_result(pkg_name, level):
    """Create a PackageScanResult at the given effective level."""
    if level == RiskLevel.CLEAN:
        return PackageScanResult(package_name=pkg_name, version="", findings=[])
    return PackageScanResult(
        package_name=pkg_name,
        version="",
        findings=[Finding(level=level, file_path="f.py", line=1, description="test")],
    )


@patch("pipguard.cli.install_from_local", return_value=0)
@patch("pipguard.cli.print_findings_report")
@patch("pipguard.cli._scan_one_package")
@patch("pipguard.cli.download_packages")
@patch("pipguard.cli.register_temp_dir")
@patch("pipguard.cli.install_signal_handlers")
class TestCmdInstallGate:

    def test_clean_package_exits_0(
        self, mock_sig, mock_reg, mock_dl, mock_scan, mock_report, mock_install, tmp_path
    ):
        """CLEAN result → exit 0, install proceeds."""
        mock_dl.return_value = ([str(tmp_path / "requests-2.28.0-py3-none-any.whl")], [])
        mock_scan.return_value = _make_scan_result("requests", RiskLevel.CLEAN)
        rc = cmd_install(_make_args())
        assert rc == 0
        mock_install.assert_called_once()

    def test_critical_finding_exits_1(
        self, mock_sig, mock_reg, mock_dl, mock_scan, mock_report, mock_install, tmp_path
    ):
        """CRITICAL finding without --force → exit 1, install blocked."""
        mock_dl.return_value = ([str(tmp_path / "evil-1.0-py3-none-any.whl")], [])
        mock_scan.return_value = _make_scan_result("evil", RiskLevel.CRITICAL)
        rc = cmd_install(_make_args(packages=["evil"]))
        assert rc == 1
        mock_install.assert_not_called()

    def test_high_finding_exits_1(
        self, mock_sig, mock_reg, mock_dl, mock_scan, mock_report, mock_install, tmp_path
    ):
        """HIGH finding without --force → exit 1."""
        mock_dl.return_value = ([str(tmp_path / "evil-1.0-py3-none-any.whl")], [])
        mock_scan.return_value = _make_scan_result("evil", RiskLevel.HIGH)
        rc = cmd_install(_make_args(packages=["evil"]))
        assert rc == 1
        mock_install.assert_not_called()

    def test_critical_with_force_exits_0(
        self, mock_sig, mock_reg, mock_dl, mock_scan, mock_report, mock_install, tmp_path
    ):
        """CRITICAL + --force → install proceeds, exit 0."""
        mock_dl.return_value = ([str(tmp_path / "evil-1.0-py3-none-any.whl")], [])
        mock_scan.return_value = _make_scan_result("evil", RiskLevel.CRITICAL)
        rc = cmd_install(_make_args(packages=["evil"], force=True))
        assert rc == 0
        mock_install.assert_called_once()

    def test_medium_with_yes_exits_0(
        self, mock_sig, mock_reg, mock_dl, mock_scan, mock_report, mock_install, tmp_path
    ):
        """MEDIUM + --yes → no prompt, install proceeds, exit 0."""
        mock_dl.return_value = ([str(tmp_path / "pkg-1.0-py3-none-any.whl")], [])
        mock_scan.return_value = _make_scan_result("pkg", RiskLevel.MEDIUM)
        rc = cmd_install(_make_args(yes=True))
        assert rc == 0
        mock_install.assert_called_once()

    def test_scan_exception_is_medium_not_silent(
        self, mock_sig, mock_reg, mock_dl, mock_scan, mock_report, mock_install, tmp_path
    ):
        """Regression: scan exception must produce MEDIUM result, not be silently dropped."""
        mock_dl.return_value = ([str(tmp_path / "evil-1.0-py3-none-any.whl")], [])
        mock_scan.side_effect = RuntimeError("boom")
        # MEDIUM result means _confirm_install would be called; --yes skips the prompt
        rc = cmd_install(_make_args(yes=True))
        # Should NOT exit 0 silently with a clean result — scan error → MEDIUM → prompt/block
        # With --yes it proceeds, but the point is the result was not dropped
        mock_report.assert_called_once()
        reported_results = mock_report.call_args[0][0]
        assert len(reported_results) == 1
        assert reported_results[0].effective_level == RiskLevel.MEDIUM

    def test_verbose_flag_is_passed_to_report(
        self, mock_sig, mock_reg, mock_dl, mock_scan, mock_report, mock_install, tmp_path
    ):
        mock_dl.return_value = ([str(tmp_path / "pkg-1.0-py3-none-any.whl")], [])
        mock_scan.return_value = _make_scan_result("pkg", RiskLevel.CLEAN)
        rc = cmd_install(_make_args(verbose=True))
        assert rc == 0
        assert mock_report.call_args.kwargs["verbose"] is True

    def test_show_pip_output_flag_is_passed_to_installer(
        self, mock_sig, mock_reg, mock_dl, mock_scan, mock_report, mock_install, tmp_path
    ):
        mock_dl.return_value = ([str(tmp_path / "pkg-1.0-py3-none-any.whl")], [])
        mock_scan.return_value = _make_scan_result("pkg", RiskLevel.CLEAN)
        rc = cmd_install(_make_args(show_pip_output=True))
        assert rc == 0
        assert mock_install.call_args.kwargs["show_pip_output"] is True

    def test_sandbox_flag_passed_to_installer(
        self, mock_sig, mock_reg, mock_dl, mock_scan, mock_report, mock_install, tmp_path
    ):
        mock_dl.return_value = ([str(tmp_path / "pkg-1.0-py3-none-any.whl")], [])
        mock_scan.return_value = _make_scan_result("pkg", RiskLevel.CLEAN)
        rc = cmd_install(_make_args(sandbox=True))
        assert rc == 0
        assert mock_install.call_args.kwargs["sandbox"] is True

    def test_sdist_rejected_without_flag(
        self, mock_sig, mock_reg, mock_dl, mock_scan, mock_report, mock_install, tmp_path
    ):
        """sdist packages without --allow-sdist → exit 2."""
        mock_dl.return_value = ([], ["litellm"])
        rc = cmd_install(_make_args(packages=["litellm"]))
        assert rc == 2
        mock_install.assert_not_called()

    def test_fail_on_vuln_blocks_clean_package_with_cve(
        self, mock_sig, mock_reg, mock_dl, mock_scan, mock_report, mock_install, tmp_path
    ):
        """A behaviourally-CLEAN package with a known CVE → exit 1 under --fail-on-vuln."""
        from pipguard.osv import OsvVulnerability
        mock_dl.return_value = ([str(tmp_path / "jinja2-2.4.1-py3-none-any.whl")], [])
        result = _make_scan_result("jinja2", RiskLevel.CLEAN)
        result.version = "2.4.1"
        result.cves = [OsvVulnerability(vuln_id="CVE-2026-1", summary="XSS")]
        mock_scan.return_value = result
        rc = cmd_install(_make_args(packages=["jinja2"], fail_on_vuln=True))
        assert rc == 1
        mock_install.assert_not_called()

    def test_known_cve_informational_does_not_block(
        self, mock_sig, mock_reg, mock_dl, mock_scan, mock_report, mock_install, tmp_path
    ):
        """--check-vulns without --fail-on-vuln surfaces CVEs but still installs."""
        from pipguard.osv import OsvVulnerability
        mock_dl.return_value = ([str(tmp_path / "jinja2-2.4.1-py3-none-any.whl")], [])
        result = _make_scan_result("jinja2", RiskLevel.CLEAN)
        result.cves = [OsvVulnerability(vuln_id="CVE-2026-1", summary="XSS")]
        mock_scan.return_value = result
        rc = cmd_install(_make_args(packages=["jinja2"], check_vulns=True))
        assert rc == 0
        mock_install.assert_called_once()

    def test_scan_receives_check_vulns_flag(
        self, mock_sig, mock_reg, mock_dl, mock_scan, mock_report, mock_install, tmp_path
    ):
        """--check-vulns must be threaded through to _scan_one_package."""
        mock_dl.return_value = ([str(tmp_path / "requests-2.31.0-py3-none-any.whl")], [])
        mock_scan.return_value = _make_scan_result("requests", RiskLevel.CLEAN)
        cmd_install(_make_args(packages=["requests"], check_vulns=True))
        # 4th positional arg to _scan_one_package is check_vulns
        assert mock_scan.call_args[0][3] is True

    @patch("pipguard.cli.load_policy")
    def test_policy_seed_allowlist_is_applied(
        self,
        mock_load_policy,
        mock_sig,
        mock_reg,
        mock_dl,
        mock_scan,
        mock_report,
        mock_install,
        tmp_path,
    ):
        mock_dl.return_value = ([str(tmp_path / "corp-auth-sdk-1.0-py3-none-any.whl")], [])
        mock_scan.return_value = PackageScanResult(
            package_name="corp-auth-sdk",
            version="",
            findings=[Finding(level=RiskLevel.HIGH, file_path="f.py", line=1, description="test")],
            is_allowlisted=True,
        )
        mock_load_policy.return_value = types.SimpleNamespace(
            require_hashes=False,
            allow_vcs_pinned=True,
            allow_direct_url_pinned=True,
            binary_only="prompt",
            intel_feed="",
            intel_enforce=False,
            seed_allowlist=["corp-auth-sdk"],
        )
        rc = cmd_install(_make_args(packages=["corp-auth-sdk"], yes=True))
        assert rc == 0

    def test_policy_blocks_binary_only_wheel(
        self, mock_sig, mock_reg, mock_dl, mock_scan, mock_report, mock_install, tmp_path
    ):
        policy = tmp_path / "pipguard.toml"
        policy.write_text("[install]\nbinary_only = 'block'\n")
        mock_dl.return_value = ([str(tmp_path / "binpkg-1.0-py3-none-any.whl")], [])
        mock_scan.return_value = PackageScanResult(
            package_name="binpkg",
            version="",
            findings=[Finding(level=RiskLevel.MEDIUM, file_path="x.so", line=0, description="binary-only")],
            is_binary_only=True,
        )
        rc = cmd_install(_make_args(packages=["binpkg"], policy=str(policy), yes=True))
        assert rc == 1
        mock_install.assert_not_called()

    @patch("pipguard.cli.load_intel_feed")
    def test_intel_feed_blocks_package(
        self, mock_intel, mock_sig, mock_reg, mock_dl, mock_scan, mock_report, mock_install, tmp_path
    ):
        mock_intel.return_value = {("evilpkg", "1.0.0"): "known malware sample"}
        mock_dl.return_value = ([str(tmp_path / "evilpkg-1.0.0-py3-none-any.whl")], [])
        rc = cmd_install(_make_args(packages=["evilpkg==1.0.0"], enforce_intel=True, intel_feed="feed.json"))
        assert rc == 1
        mock_scan.assert_not_called()
        mock_install.assert_not_called()

    @patch("pipguard.cli.load_intel_feed")
    def test_intel_enforced_without_feed_does_not_block(
        self, mock_intel, mock_sig, mock_reg, mock_dl, mock_scan, mock_report, mock_install, tmp_path
    ):
        mock_dl.return_value = ([str(tmp_path / "okpkg-1.0.0-py3-none-any.whl")], [])
        mock_scan.return_value = _make_scan_result("okpkg", RiskLevel.CLEAN)
        rc = cmd_install(_make_args(packages=["okpkg"], enforce_intel=True, intel_feed=None))
        assert rc == 0
        mock_intel.assert_not_called()


class TestValidateRequirementsFilePEP508:
    """Regression tests for PEP 508 direct URL dependencies."""

    def _write(self, tmp_path, content):
        req = tmp_path / "requirements.txt"
        req.write_text(content)
        return str(req)

    def test_pep508_https_url_returns_2(self, tmp_path):
        """pkg @ https://... must be rejected (exit 2)."""
        f = self._write(tmp_path, "requests @ https://example.com/requests.whl\n")
        assert _validate_requirements_file(f) == 2

    def test_pep508_file_url_returns_2(self, tmp_path):
        """pkg @ file:///... must be rejected (exit 2)."""
        f = self._write(tmp_path, "mypkg @ file:///home/user/mypkg-1.0.whl\n")
        assert _validate_requirements_file(f) == 2

    def test_normal_pinned_dep_returns_0(self, tmp_path):
        """Normal pinned dep without @ must still pass."""
        f = self._write(tmp_path, "requests==2.28.0\n")
        assert _validate_requirements_file(f) == 0


# ── Network-gated integration tests ──────────────────────────────────────────

NETWORK_TESTS = os.environ.get("PIPGUARD_NETWORK_TESTS", "").lower() in ("1", "true", "yes")
skip_no_network = pytest.mark.skipif(
    not NETWORK_TESTS,
    reason="Set PIPGUARD_NETWORK_TESTS=1 to run network tests",
)


@skip_no_network
class TestNetworkIntegration:
    """
    Integration tests that require network access and a real pip.
    Run with: PIPGUARD_NETWORK_TESTS=1 pytest tests/test_cli.py -v
    """

    def test_clean_package_exits_0(self):
        """A known-clean package installs successfully."""
        import subprocess
        result = subprocess.run(
            [sys.executable, "-m", "pipguard", "install", "--yes", "six==1.16.0"],
            capture_output=True, text=True,
        )
        assert result.returncode == 0, (
            f"Expected exit 0 for clean package, got {result.returncode}\n"
            f"stdout: {result.stdout}\nstderr: {result.stderr}"
        )


# ── scan-feed subcommand (reporter workflow, #40/#41) ────────────────────────

def _make_feed_args(**kwargs):
    defaults = dict(
        feed="updates",
        limit=20,
        min_level="high",
        allow=[],
        check_vulns=False,
        verbose=False,
        policy=None,
    )
    defaults.update(kwargs)
    return types.SimpleNamespace(**defaults)


@patch("pipguard.cli.print_findings_report")
@patch("pipguard.cli._scan_one_package")
@patch("pipguard.cli.download_for_scan")
@patch("pipguard.cli.fetch_feed")
@patch("pipguard.cli.register_temp_dir")
@patch("pipguard.cli.install_signal_handlers")
class TestCmdScanFeed:

    def test_high_risk_entry_is_flagged_exit_1(
        self, mock_sig, mock_reg, mock_fetch, mock_dl, mock_scan, mock_report, tmp_path
    ):
        mock_fetch.return_value = _FEED_XML
        mock_dl.return_value = ([str(tmp_path / "evilpkg-1.2.3-py3-none-any.whl")], [])
        result = PackageScanResult(
            "evilpkg", "1.2.3",
            findings=[Finding(level=RiskLevel.CRITICAL, file_path="setup.py", line=1, description="x")],
        )
        mock_scan.return_value = result
        rc = cmd_scan_feed(_make_feed_args())
        assert rc == 1

    def test_clean_feed_exit_0(
        self, mock_sig, mock_reg, mock_fetch, mock_dl, mock_scan, mock_report, tmp_path
    ):
        mock_fetch.return_value = _FEED_XML
        mock_dl.return_value = ([str(tmp_path / "evilpkg-1.2.3-py3-none-any.whl")], [])
        mock_scan.return_value = PackageScanResult("evilpkg", "1.2.3", findings=[])
        rc = cmd_scan_feed(_make_feed_args())
        assert rc == 0

    def test_below_threshold_not_flagged(
        self, mock_sig, mock_reg, mock_fetch, mock_dl, mock_scan, mock_report, tmp_path
    ):
        """A MEDIUM result with default --min-level high is not a candidate."""
        mock_fetch.return_value = _FEED_XML
        mock_dl.return_value = ([str(tmp_path / "evilpkg-1.2.3-py3-none-any.whl")], [])
        mock_scan.return_value = PackageScanResult(
            "evilpkg", "1.2.3",
            findings=[Finding(level=RiskLevel.MEDIUM, file_path="m.py", line=1, description="x")],
        )
        rc = cmd_scan_feed(_make_feed_args(min_level="high"))
        assert rc == 0

    def test_fetch_failure_exit_2(
        self, mock_sig, mock_reg, mock_fetch, mock_dl, mock_scan, mock_report, tmp_path
    ):
        mock_fetch.return_value = ""
        rc = cmd_scan_feed(_make_feed_args())
        assert rc == 2
        mock_dl.assert_not_called()

    def test_empty_feed_exit_2(
        self, mock_sig, mock_reg, mock_fetch, mock_dl, mock_scan, mock_report, tmp_path
    ):
        mock_fetch.return_value = "<rss><channel></channel></rss>"
        rc = cmd_scan_feed(_make_feed_args())
        assert rc == 2
        mock_dl.assert_not_called()

    def test_limit_zero_scans_all(
        self, mock_sig, mock_reg, mock_fetch, mock_dl, mock_scan, mock_report, tmp_path
    ):
        two = (
            '<rss><channel>'
            '<item><title>a 1.0</title><link>https://pypi.org/project/a/1.0/</link></item>'
            '<item><title>b 2.0</title><link>https://pypi.org/project/b/2.0/</link></item>'
            '</channel></rss>'
        )
        mock_fetch.return_value = two
        mock_dl.return_value = ([], [])
        mock_scan.return_value = PackageScanResult("a", "1.0", findings=[])
        cmd_scan_feed(_make_feed_args(limit=0))
        specs = mock_dl.call_args[0][0]
        assert specs == ["a==1.0", "b==2.0"]

    def test_limit_truncates_entries(
        self, mock_sig, mock_reg, mock_fetch, mock_dl, mock_scan, mock_report, tmp_path
    ):
        two = (
            '<rss><channel>'
            '<item><title>a 1.0</title><link>https://pypi.org/project/a/1.0/</link></item>'
            '<item><title>b 2.0</title><link>https://pypi.org/project/b/2.0/</link></item>'
            '</channel></rss>'
        )
        mock_fetch.return_value = two
        mock_dl.return_value = ([], [])
        mock_scan.return_value = PackageScanResult("a", "1.0", findings=[])
        cmd_scan_feed(_make_feed_args(limit=1))
        # only 1 spec should be passed to download_packages
        specs = mock_dl.call_args[0][0]
        assert specs == ["a==1.0"]

    def test_all_downloads_skipped_exit_2(
        self, mock_sig, mock_reg, mock_fetch, mock_dl, mock_scan, mock_report, tmp_path
    ):
        """When every feed entry fails to download, exit 2 with nothing scanned."""
        mock_fetch.return_value = _FEED_XML
        mock_dl.return_value = ([], ["evilpkg==1.2.3"])
        rc = cmd_scan_feed(_make_feed_args())
        assert rc == 2
        mock_scan.assert_not_called()

    def test_skipped_downloads_reported_and_scan_continues(
        self, mock_sig, mock_reg, mock_fetch, mock_dl, mock_scan, mock_report, tmp_path, capsys
    ):
        """Undownloadable entries are reported but don't abort scanning the rest."""
        mock_fetch.return_value = _FEED_XML
        mock_dl.return_value = (
            [str(tmp_path / "evilpkg-1.2.3-py3-none-any.whl")], ["unresolvable==9.9"]
        )
        mock_scan.return_value = PackageScanResult("evilpkg", "1.2.3", findings=[])
        rc = cmd_scan_feed(_make_feed_args())
        assert rc == 0
        assert "unresolvable==9.9" in capsys.readouterr().err

    def test_scan_exception_is_captured_not_fatal(
        self, mock_sig, mock_reg, mock_fetch, mock_dl, mock_scan, mock_report, tmp_path
    ):
        """A per-package scan crash becomes a MEDIUM fail-safe result, not a raise."""
        mock_fetch.return_value = _FEED_XML
        mock_dl.return_value = ([str(tmp_path / "evilpkg-1.2.3-py3-none-any.whl")], [])
        mock_scan.side_effect = RuntimeError("boom")
        rc = cmd_scan_feed(_make_feed_args(min_level="high"))
        # MEDIUM fail-safe < high threshold → exit 0, but report still produced
        assert rc == 0
        mock_report.assert_called_once()


class TestMainDispatch:
    @patch("pipguard.cli.cmd_scan_feed", return_value=0)
    def test_main_routes_scan_feed(self, mock_cmd):
        from pipguard.cli import main
        with patch("sys.argv", ["pipguard", "scan-feed", "--feed", "updates"]):
            assert main() == 0
        mock_cmd.assert_called_once()

    def test_parser_scan_feed_defaults(self):
        args = build_parser().parse_args(["scan-feed"])
        assert args.command == "scan-feed"
        assert args.feed == "updates"
        assert args.limit == 20
        assert args.min_level == "high"
