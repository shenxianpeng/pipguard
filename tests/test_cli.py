"""
Tests for pipguard.cli — argument parsing, requirements validation,
package name extraction, and gate logic.

Network-dependent tests (actual pip download) are gated by the
PIPGUARD_NETWORK_TESTS environment variable.
"""

import os
import sys
import tempfile
import pytest

sys.path.insert(0, os.path.join(os.path.dirname(__file__), ".."))

from pipguard.cli import (
    _pkg_name_from_filename,
    _validate_requirements_file,
    build_parser,
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

    def test_version_flag(self, capsys):
        parser = build_parser()
        with pytest.raises(SystemExit) as exc:
            parser.parse_args(["--version"])
        assert exc.value.code == 0

    def test_no_args_exits(self, capsys):
        parser = build_parser()
        with pytest.raises(SystemExit):
            parser.parse_args([])


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
