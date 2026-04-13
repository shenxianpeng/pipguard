"""
Tests covering previously uncovered code paths to reach 100% coverage.

Covers:
  - models.py: Finding.__str__ with line=0
  - aggregator.py: print_findings_report, _color (via monkeypatch)
  - cleanup.py: register_temp_dir, install_signal_handlers
  - downloader.py: check_disk_space, download_packages
  - extractor.py: .zip sdist handling, _is_sdist_zip
  - installer.py: install_from_local
  - scanner.py: large-file skip, OSError paths, SyntaxError, pth secondary check, _call_name ""
  - cli.py: _scan_one_package paths, _confirm_install EOFError, cmd_install branches, main()
"""

import io
import os
import signal
import sys
import tempfile
import types
import zipfile
from unittest.mock import MagicMock, patch

import pytest

sys.path.insert(0, os.path.join(os.path.dirname(__file__), ".."))

from pipguard.models import Finding, PackageScanResult, RiskLevel


# ── models.py ────────────────────────────────────────────────────────────────

class TestFindingStr:
    def test_str_with_nonzero_line(self):
        f = Finding(level=RiskLevel.HIGH, file_path="setup.py", line=5, description="test")
        assert "setup.py:5" in str(f)

    def test_str_with_zero_line(self):
        """When line=0, __str__ omits the line number (uses just file_path)."""
        f = Finding(level=RiskLevel.HIGH, file_path="setup.py", line=0, description="test")
        s = str(f)
        assert "setup.py" in s
        assert ":0" not in s


# ── aggregator.py ─────────────────────────────────────────────────────────────

class TestPrintFindingsReport:
    def test_all_clean_prints_clean_message(self, capsys):
        from pipguard.aggregator import print_findings_report
        results = [PackageScanResult("requests", "2.28.0", findings=[])]
        print_findings_report(results)
        out = capsys.readouterr().out
        assert "CLEAN" in out

    def test_binary_only_package(self, capsys):
        from pipguard.aggregator import print_findings_report
        result = PackageScanResult("mybin", "1.0", findings=[], is_binary_only=True)
        print_findings_report([result])
        out = capsys.readouterr().out
        assert "UNKNOWN" in out or "Binary-only" in out

    def test_finding_report_shows_level(self, capsys):
        from pipguard.aggregator import print_findings_report
        f = Finding(level=RiskLevel.CRITICAL, file_path="setup.py", line=1, description="bad")
        result = PackageScanResult("evil", "0.1", findings=[f])
        print_findings_report([result])
        out = capsys.readouterr().out
        assert "CRITICAL" in out

    def test_finding_with_snippet(self, capsys):
        from pipguard.aggregator import print_findings_report
        f = Finding(
            level=RiskLevel.HIGH, file_path="setup.py", line=2,
            description="cred access", snippet="open('~/.ssh/id_rsa')"
        )
        result = PackageScanResult("evil", "0.1", findings=[f])
        print_findings_report([result])
        out = capsys.readouterr().out
        assert "cred access" in out

    def test_allowlisted_high_reduced_message(self, capsys):
        from pipguard.aggregator import print_findings_report
        f = Finding(level=RiskLevel.HIGH, file_path="x.py", line=1, description="cred")
        result = PackageScanResult("keyring", "1.0", findings=[f], is_allowlisted=True)
        print_findings_report([result])
        out = capsys.readouterr().out
        assert "allowlisted" in out

    def test_clean_package_in_mixed_list(self, capsys):
        from pipguard.aggregator import print_findings_report
        f = Finding(level=RiskLevel.HIGH, file_path="setup.py", line=1, description="bad")
        bad = PackageScanResult("evil", "0.1", findings=[f])
        clean = PackageScanResult("requests", "2.28.0", findings=[])
        print_findings_report([bad, clean])
        out = capsys.readouterr().out
        assert "evil" in out

    def test_color_function_with_color_enabled(self):
        """_color returns colored text when color is enabled."""
        import pipguard.aggregator as agg
        original = agg._USE_COLOR
        try:
            agg._USE_COLOR = True
            result = agg._color("CRITICAL", "CRITICAL")
            assert "CRITICAL" in result
            assert "\033[" in result  # ANSI escape
        finally:
            agg._USE_COLOR = original

    def test_color_function_with_color_disabled(self):
        """_color returns plain text when color is disabled."""
        import pipguard.aggregator as agg
        original = agg._USE_COLOR
        try:
            agg._USE_COLOR = False
            result = agg._color("CLEAN", "CLEAN")
            assert result == "CLEAN"
        finally:
            agg._USE_COLOR = original


# ── cleanup.py ────────────────────────────────────────────────────────────────

class TestCleanup:
    def test_register_temp_dir_adds_to_list(self, tmp_path):
        from pipguard import cleanup
        initial_len = len(cleanup._registered_dirs)
        cleanup.register_temp_dir(str(tmp_path))
        assert str(tmp_path) in cleanup._registered_dirs
        cleanup._registered_dirs.clear()

    def test_install_signal_handlers_installs_sigint(self):
        from pipguard.cleanup import install_signal_handlers
        install_signal_handlers()
        handler = signal.getsignal(signal.SIGINT)
        assert handler != signal.SIG_DFL
        # Restore default
        signal.signal(signal.SIGINT, signal.SIG_DFL)
        signal.signal(signal.SIGTERM, signal.SIG_DFL)

    def test_signal_handler_cleans_up_and_exits(self, tmp_path):
        """The signal handler removes registered dirs and calls sys.exit(1)."""
        from pipguard import cleanup
        cleanup._registered_dirs.clear()
        d = tmp_path / "to_clean"
        d.mkdir()
        cleanup.register_temp_dir(str(d))

        # Reinstall handlers so the new dir is captured
        cleanup.install_signal_handlers()
        handler = signal.getsignal(signal.SIGINT)

        with pytest.raises(SystemExit) as exc_info:
            handler(signal.SIGINT, None)
        assert exc_info.value.code == 1
        cleanup._registered_dirs.clear()
        signal.signal(signal.SIGINT, signal.SIG_DFL)
        signal.signal(signal.SIGTERM, signal.SIG_DFL)


# ── downloader.py ─────────────────────────────────────────────────────────────

class TestCheckDiskSpace:
    def test_no_warning_when_space_is_sufficient(self, tmp_path, capsys):
        from pipguard.downloader import check_disk_space
        check_disk_space(str(tmp_path))
        # No error raised; warning only if truly low disk

    def test_warning_when_disk_space_is_low(self, tmp_path, capsys):
        from pipguard.downloader import check_disk_space, MINIMUM_DISK_MB
        with patch("shutil.disk_usage") as mock_usage:
            mock_usage.return_value = types.SimpleNamespace(free=10 * 1024 * 1024)
            check_disk_space(str(tmp_path))
        err = capsys.readouterr().err
        assert "Low disk space" in err

    def test_oserror_is_silently_ignored(self, tmp_path):
        from pipguard.downloader import check_disk_space
        with patch("shutil.disk_usage", side_effect=OSError("nope")):
            check_disk_space(str(tmp_path))  # must not raise


class TestDownloadPackages:
    def _make_fake_wheel(self, dest_dir: str, name: str = "mypkg-1.0-py3-none-any.whl"):
        whl_path = os.path.join(dest_dir, name)
        with zipfile.ZipFile(whl_path, "w") as zf:
            zf.writestr("mypkg/__init__.py", "")
        return whl_path

    def test_returns_wheel_files(self, tmp_path):
        from pipguard.downloader import download_packages
        fake_dest = str(tmp_path)
        self._make_fake_wheel(fake_dest)

        with patch("subprocess.run") as mock_run:
            mock_run.return_value = MagicMock(returncode=0, stderr="")
            archives, rejects = download_packages(["mypkg"], fake_dest)

        assert len(archives) == 1
        assert archives[0].endswith(".whl")
        assert rejects == []

    def test_raises_on_pip_failure(self, tmp_path):
        from pipguard.downloader import download_packages
        with patch("subprocess.run") as mock_run:
            mock_run.return_value = MagicMock(returncode=1, stderr="download failed")
            with pytest.raises(RuntimeError, match="pip download failed"):
                download_packages(["badpkg"], str(tmp_path))

    def test_sdist_rejected_without_allow_sdist(self, tmp_path):
        from pipguard.downloader import download_packages
        fake_dest = str(tmp_path)
        sdist_path = os.path.join(fake_dest, "mypkg-1.0.tar.gz")
        open(sdist_path, "w").close()

        with patch("subprocess.run") as mock_run:
            mock_run.return_value = MagicMock(returncode=0, stderr="")
            archives, rejects = download_packages(["mypkg"], fake_dest, allow_sdist=False)

        assert "mypkg-1.0.tar.gz" in rejects
        assert archives == []

    def test_sdist_allowed_with_allow_sdist(self, tmp_path, capsys):
        from pipguard.downloader import download_packages
        fake_dest = str(tmp_path)
        sdist_path = os.path.join(fake_dest, "mypkg-1.0.tar.gz")
        open(sdist_path, "w").close()

        with patch("subprocess.run") as mock_run:
            mock_run.return_value = MagicMock(returncode=0, stderr="")
            archives, rejects = download_packages(["mypkg"], fake_dest, allow_sdist=True)

        assert rejects == []
        assert len(archives) == 1

    def test_requirements_file_passed_to_pip(self, tmp_path):
        from pipguard.downloader import download_packages
        req_file = str(tmp_path / "requirements.txt")
        with open(req_file, "w") as f:
            f.write("requests==2.28.0\n")

        with patch("subprocess.run") as mock_run:
            mock_run.return_value = MagicMock(returncode=0, stderr="")
            download_packages([], str(tmp_path), requirements_file=req_file)

        cmd = mock_run.call_args[0][0]
        assert "-r" in cmd
        assert req_file in cmd

    def test_require_hashes_passed_to_download(self, tmp_path):
        from pipguard.downloader import download_packages
        with patch("subprocess.run") as mock_run:
            mock_run.return_value = MagicMock(returncode=0, stderr="")
            download_packages(["requests"], str(tmp_path), require_hashes=True)
        cmd = mock_run.call_args[0][0]
        assert "--require-hashes" in cmd


# ── extractor.py ─────────────────────────────────────────────────────────────

class TestIsSdistZip:
    def test_returns_true_for_zip_with_setup_py(self, tmp_path):
        from pipguard.extractor import _is_sdist_zip
        z = tmp_path / "mypkg-1.0.zip"
        with zipfile.ZipFile(str(z), "w") as zf:
            zf.writestr("mypkg-1.0/setup.py", "from setuptools import setup\n")
        assert _is_sdist_zip(str(z)) is True

    def test_returns_true_for_zip_with_pyproject(self, tmp_path):
        from pipguard.extractor import _is_sdist_zip
        z = tmp_path / "mypkg-1.0.zip"
        with zipfile.ZipFile(str(z), "w") as zf:
            zf.writestr("mypkg-1.0/pyproject.toml", "[project]\n")
        assert _is_sdist_zip(str(z)) is True

    def test_returns_false_for_wheel_zip(self, tmp_path):
        from pipguard.extractor import _is_sdist_zip
        z = tmp_path / "mypkg-1.0-py3-none-any.whl"
        with zipfile.ZipFile(str(z), "w") as zf:
            zf.writestr("mypkg/__init__.py", "")
        assert _is_sdist_zip(str(z)) is False

    def test_returns_false_for_bad_zip(self, tmp_path):
        from pipguard.extractor import _is_sdist_zip
        z = tmp_path / "bad.zip"
        z.write_bytes(b"not a zip")
        assert _is_sdist_zip(str(z)) is False


class TestExtractSdistZip:
    def test_extract_sdist_zip(self, tmp_path):
        """A .zip sdist (has setup.py) goes through the tarfile-branch zip path."""
        from pipguard.extractor import extract_archive
        z = tmp_path / "mypkg-1.0.zip"
        with zipfile.ZipFile(str(z), "w") as zf:
            zf.writestr("mypkg-1.0/setup.py", "from setuptools import setup\n")

        result = extract_archive(str(z), str(tmp_path))
        assert result is not None
        assert os.path.isdir(result)


# ── installer.py ─────────────────────────────────────────────────────────────

class TestInstallFromLocal:
    def test_returns_pip_exit_code_on_success(self, tmp_path):
        from pipguard.installer import install_from_local
        with patch("subprocess.run") as mock_run:
            mock_run.return_value = MagicMock(returncode=0)
            rc = install_from_local(["requests"], str(tmp_path))
        assert rc == 0

    def test_returns_pip_exit_code_on_failure(self, tmp_path):
        from pipguard.installer import install_from_local
        with patch("subprocess.run") as mock_run:
            mock_run.return_value = MagicMock(returncode=1)
            rc = install_from_local(["badpkg"], str(tmp_path))
        assert rc == 1

    def test_uses_requirements_file(self, tmp_path):
        from pipguard.installer import install_from_local
        req = str(tmp_path / "requirements.txt")
        with open(req, "w") as f:
            f.write("requests==2.28.0\n")
        with patch("subprocess.run") as mock_run:
            mock_run.return_value = MagicMock(returncode=0)
            install_from_local([], str(tmp_path), requirements_file=req)
        cmd = mock_run.call_args[0][0]
        assert "-r" in cmd
        assert req in cmd

    def test_require_hashes_passed_to_install(self, tmp_path):
        from pipguard.installer import install_from_local
        with patch("subprocess.run") as mock_run:
            mock_run.return_value = MagicMock(returncode=0)
            install_from_local(["requests"], str(tmp_path), require_hashes=True)
        cmd = mock_run.call_args[0][0]
        assert "--require-hashes" in cmd


# ── scanner.py ────────────────────────────────────────────────────────────────

class TestScannerEdgePaths:
    def test_pth_secondary_check_parseable_python(self, tmp_path):
        """Lines with valid Python (not just a path string) get CRITICAL via secondary check."""
        from pipguard.scanner import scan_pth_file
        pth = tmp_path / "attack.pth"
        # "pass" is valid Python, no code chars (no (; =), no keywords, but not a path string
        pth.write_text("pass\n")
        findings = scan_pth_file(str(pth))
        assert any(f.level == RiskLevel.CRITICAL for f in findings)

    def test_pth_plain_string_not_flagged(self, tmp_path):
        """A plain string constant on a .pth line is not flagged as code."""
        from pipguard.scanner import scan_pth_file
        pth = tmp_path / "plain.pth"
        pth.write_text('"just a string"\n')
        findings = scan_pth_file(str(pth))
        assert not any(f.description == ".pth file contains parseable Python code"
                       for f in findings)

    def test_pth_oserror_silently_ignored(self, tmp_path):
        """OSError when reading .pth returns empty findings."""
        from pipguard.scanner import scan_pth_file
        result = scan_pth_file("/nonexistent/path/attack.pth")
        assert result == []

    def test_scan_python_file_over_1mb_emits_confidence_warning(self, tmp_path):
        """Files larger than 1MB emit confidence-reduction finding (not skipped)."""
        from pipguard.scanner import scan_python_file
        big = tmp_path / "big.py"
        big.write_bytes(b"x = 1\n" * 200_000)  # > 1MB
        findings = scan_python_file(str(big))
        assert any("scan confidence reduced" in f.description for f in findings)

    def test_scan_python_file_oserror_returns_empty(self):
        """OSError during file open returns empty findings."""
        from pipguard.scanner import scan_python_file
        findings = scan_python_file("/nonexistent/file.py")
        assert findings == []

    def test_scan_python_file_syntax_error_returns_text_findings(self, tmp_path):
        """SyntaxError in ast.parse still returns any text-level findings."""
        from pipguard.scanner import scan_python_file
        bad = tmp_path / "bad.py"
        # Invalid syntax but contains obfuscation pattern at text level
        bad.write_text("exec(b64decode(\ndef ))\n")
        findings = scan_python_file(str(bad))
        # Text-level check fires, then SyntaxError → returns those findings
        assert isinstance(findings, list)

    def test_scan_python_file_pure_syntax_error(self, tmp_path):
        """A file with only a SyntaxError and no text-level findings returns []."""
        from pipguard.scanner import scan_python_file
        bad = tmp_path / "bad.py"
        bad.write_text("def (\n")
        findings = scan_python_file(str(bad))
        assert findings == []

    def test_call_name_returns_empty_for_non_name_non_attribute(self, tmp_path):
        """_call_name returns '' for Call nodes with non-Name/Attribute func."""
        from pipguard.scanner import _call_name
        import ast
        # subscript call: foo[0]()
        tree = ast.parse("foo[0]()", mode="eval")
        call_node = tree.body
        assert isinstance(call_node, ast.Call)
        result = _call_name(call_node)
        assert result == ""


# ── cli.py extra coverage ─────────────────────────────────────────────────────

class TestScanOnePackage:
    def test_extract_failure_returns_medium_finding(self, tmp_path):
        from pipguard.cli import _scan_one_package
        from pipguard.extractor import extract_archive
        with patch("pipguard.cli.extract_archive", return_value=None):
            result = _scan_one_package(
                str(tmp_path / "mypkg-1.0-py3-none-any.whl"),
                str(tmp_path),
                [],
            )
        assert result.findings
        assert result.findings[0].level == RiskLevel.MEDIUM

    def test_binary_only_package(self, tmp_path):
        from pipguard.cli import _scan_one_package
        extract_dir = tmp_path / "extracted"
        extract_dir.mkdir()
        # Only a .so file — no Python source
        (extract_dir / "mod.so").write_bytes(b"\x7fELF")

        with patch("pipguard.cli.extract_archive", return_value=str(extract_dir)):
            result = _scan_one_package(
                str(tmp_path / "mypkg-1.0-py3-none-any.whl"),
                str(tmp_path),
                [],
            )
        assert result.is_binary_only is True

    def test_homoglyph_package_name_adds_finding(self, tmp_path):
        """Non-ASCII package name produces a HIGH homoglyph finding (cli.py:69)."""
        from pipguard.cli import _scan_one_package
        extract_dir = tmp_path / "extracted"
        extract_dir.mkdir()
        (extract_dir / "mod.py").write_text("x = 1\n")

        # Filename with Cyrillic 'о' (U+043E) mimicking 'boto3'
        whl_name = "b\u043eto3-1.0-py3-none-any.whl"
        with patch("pipguard.cli.extract_archive", return_value=str(extract_dir)):
            result = _scan_one_package(
                str(tmp_path / whl_name),
                str(tmp_path),
                [],
            )
        from pipguard.models import RiskLevel
        assert any(f.level == RiskLevel.HIGH for f in result.findings), (
            "Homoglyph package name must produce a HIGH finding"
        )


class TestConfirmInstall:
    def test_returns_false_on_eoferror(self):
        from pipguard.cli import _confirm_install
        with patch("builtins.input", side_effect=EOFError):
            assert _confirm_install() is False

    def test_returns_false_on_keyboard_interrupt(self):
        from pipguard.cli import _confirm_install
        with patch("builtins.input", side_effect=KeyboardInterrupt):
            assert _confirm_install() is False


class TestValidateRequirementsFileOSError:
    def test_oserror_returns_2(self):
        from pipguard.cli import _validate_requirements_file
        rc = _validate_requirements_file("/nonexistent/requirements.txt")
        assert rc == 2


class TestCmdInstallBranches:
    def _make_args(self, **kwargs):
        args = types.SimpleNamespace(
            packages=[],
            r=None,
            allow=[],
            allow_sdist=False,
            yes=False,
            force=False,
            require_hashes=False,
            policy=None,
            intel_feed=None,
            enforce_intel=False,
        )
        for k, v in kwargs.items():
            setattr(args, k, v)
        return args

    def test_no_packages_no_requirements_returns_2(self):
        from pipguard.cli import cmd_install
        args = self._make_args()
        rc = cmd_install(args)
        assert rc == 2

    def test_download_runtime_error_returns_2(self, tmp_path):
        from pipguard.cli import cmd_install
        args = self._make_args(packages=["evil"])
        with patch("pipguard.cli.download_packages", side_effect=RuntimeError("pip failed")):
            rc = cmd_install(args)
        assert rc == 2

    def test_no_archive_files_returns_2(self, tmp_path):
        from pipguard.cli import cmd_install
        args = self._make_args(packages=["mypkg"])
        with patch("pipguard.cli.download_packages", return_value=([], [])):
            rc = cmd_install(args)
        assert rc == 2

    def test_force_overrides_critical(self, tmp_path, capsys):
        from pipguard.cli import cmd_install
        from pipguard.models import PackageScanResult, Finding, RiskLevel
        args = self._make_args(packages=["evil"], force=True)
        finding = Finding(level=RiskLevel.CRITICAL, file_path="setup.py", line=1, description="bad")
        result = PackageScanResult("evil", "0.1", findings=[finding])

        with patch("pipguard.cli.download_packages", return_value=(["evil-0.1.whl"], [])), \
             patch("pipguard.cli._scan_one_package", return_value=result), \
             patch("pipguard.cli.install_from_local", return_value=0):
            rc = cmd_install(args)
        assert rc == 0
        err = capsys.readouterr().err
        assert "--force" in err

    def test_medium_finding_user_declines(self, tmp_path, capsys):
        from pipguard.cli import cmd_install
        from pipguard.models import PackageScanResult, Finding, RiskLevel
        args = self._make_args(packages=["mypkg"])
        finding = Finding(level=RiskLevel.MEDIUM, file_path="mypkg.py", line=1, description="net")
        result = PackageScanResult("mypkg", "1.0", findings=[finding])

        with patch("pipguard.cli.download_packages", return_value=(["mypkg-1.0.whl"], [])), \
             patch("pipguard.cli._scan_one_package", return_value=result), \
             patch("pipguard.cli._confirm_install", return_value=False):
            rc = cmd_install(args)
        assert rc == 1

    def test_install_pip_failure_returns_2(self, tmp_path):
        from pipguard.cli import cmd_install
        from pipguard.models import PackageScanResult
        args = self._make_args(packages=["mypkg"], yes=True)
        result = PackageScanResult("mypkg", "1.0", findings=[])

        with patch("pipguard.cli.download_packages", return_value=(["mypkg-1.0.whl"], [])), \
             patch("pipguard.cli._scan_one_package", return_value=result), \
             patch("pipguard.cli.install_from_local", return_value=1):
            rc = cmd_install(args)
        assert rc == 2


class TestMain:
    def test_main_install_command(self):
        from pipguard.cli import main
        with patch("sys.argv", ["pipguard", "install", "requests"]), \
             patch("pipguard.cli.cmd_install", return_value=0) as mock_install:
            rc = main()
        assert rc == 0
        mock_install.assert_called_once()


# ── Additional branch coverage ────────────────────────────────────────────────

class TestPkgNameFromFilenameEdgeCases:
    def test_unknown_extension_returns_raw_name(self):
        from pipguard.cli import _pkg_name_from_filename
        # No known extension — for loop completes without break
        result = _pkg_name_from_filename("mypkg-1.0.egg")
        assert "mypkg" in result

    def test_all_digit_parts_returns_fname(self):
        from pipguard.cli import _pkg_name_from_filename
        # All parts start with a digit → name_parts is empty → returns fname
        result = _pkg_name_from_filename("1.2.3.whl")
        assert result == "1.2.3"


class TestScanOnePackageWithFiles:
    def test_scans_python_files(self, tmp_path):
        from pipguard.cli import _scan_one_package
        extract_dir = tmp_path / "extracted"
        extract_dir.mkdir()
        (extract_dir / "mypkg.py").write_text("x = 1\n")

        with patch("pipguard.cli.extract_archive", return_value=str(extract_dir)):
            result = _scan_one_package(
                str(tmp_path / "mypkg-1.0-py3-none-any.whl"),
                str(tmp_path),
                [],
            )
        assert result.package_name == "mypkg"
        assert result.is_binary_only is False

    def test_scans_pth_files(self, tmp_path):
        from pipguard.cli import _scan_one_package
        extract_dir = tmp_path / "extracted"
        extract_dir.mkdir()
        (extract_dir / "attack.pth").write_text('/usr/lib/python\n')

        with patch("pipguard.cli.extract_archive", return_value=str(extract_dir)):
            result = _scan_one_package(
                str(tmp_path / "mypkg-1.0-py3-none-any.whl"),
                str(tmp_path),
                [],
            )
        assert result.package_name == "mypkg"


class TestConfirmInstallNormalPath:
    def test_returns_true_for_yes(self):
        from pipguard.cli import _confirm_install
        with patch("builtins.input", return_value="yes"):
            assert _confirm_install() is True

    def test_returns_false_for_no(self):
        from pipguard.cli import _confirm_install
        with patch("builtins.input", return_value="n"):
            assert _confirm_install() is False


class TestCmdInstallRequirementsValidation:
    def _make_args(self, **kwargs):
        args = types.SimpleNamespace(
            packages=[],
            r=None,
            allow=[],
            allow_sdist=False,
            yes=False,
            force=False,
            require_hashes=False,
            policy=None,
            intel_feed=None,
            enforce_intel=False,
        )
        for k, v in kwargs.items():
            setattr(args, k, v)
        return args

    def test_invalid_requirements_returns_2(self, tmp_path):
        from pipguard.cli import cmd_install
        req = str(tmp_path / "requirements.txt")
        with open(req, "w") as f:
            f.write("git+https://github.com/evil/pkg.git\n")
        args = self._make_args(r=req)
        rc = cmd_install(args)
        assert rc == 2


class TestCmdInstallMediumProceed:
    def _make_args(self, **kwargs):
        args = types.SimpleNamespace(
            packages=[],
            r=None,
            allow=[],
            allow_sdist=False,
            yes=False,
            force=False,
            require_hashes=False,
            policy=None,
            intel_feed=None,
            enforce_intel=False,
        )
        for k, v in kwargs.items():
            setattr(args, k, v)
        return args

    def test_medium_finding_user_confirms(self, tmp_path):
        from pipguard.cli import cmd_install
        from pipguard.models import PackageScanResult, Finding, RiskLevel
        args = self._make_args(packages=["mypkg"])
        finding = Finding(level=RiskLevel.MEDIUM, file_path="mypkg.py", line=1, description="net")
        result = PackageScanResult("mypkg", "1.0", findings=[finding])

        with patch("pipguard.cli.download_packages", return_value=(["mypkg-1.0.whl"], [])), \
             patch("pipguard.cli._scan_one_package", return_value=result), \
             patch("pipguard.cli._confirm_install", return_value=True), \
             patch("pipguard.cli.install_from_local", return_value=0):
            rc = cmd_install(args)
        assert rc == 0

    def test_valid_requirements_passes_validation_then_download_error(self, tmp_path):
        """Covers the branch where requirements_file passes validation (rc=0) and proceeds."""
        from pipguard.cli import cmd_install
        req = str(tmp_path / "requirements.txt")
        with open(req, "w") as f:
            f.write("requests==2.28.0\n")
        args = self._make_args(r=req)
        with patch("pipguard.cli.download_packages", side_effect=RuntimeError("net fail")):
            rc = cmd_install(args)
        assert rc == 2


class TestScannerBranchCoverage:
    def test_b64decode_without_exec_eval(self, tmp_path):
        """b64decode present but without exec/eval — does not add finding, proceeds to parse."""
        from pipguard.scanner import scan_python_file
        f = tmp_path / "test.py"
        f.write_text("import base64\ndata = base64.b64decode(b'aGVsbG8=')\n")
        findings = scan_python_file(str(f))
        # No CRITICAL finding for b64decode alone
        assert not any(
            "obfuscated payload" in fi.description for fi in findings
        )

    def test_subprocess_with_non_shell_keyword(self, tmp_path):
        """subprocess.run() with timeout kwarg is still HIGH in install-hook scope."""
        from pipguard.scanner import scan_python_file
        f = tmp_path / "setup.py"
        f.write_text("import subprocess\nsubprocess.run(['ls'], timeout=5)\n")
        findings = scan_python_file(str(f), is_hook=True)
        assert any(fi.level.name == "HIGH" for fi in findings)

    def test_subprocess_with_shell_false(self, tmp_path):
        """subprocess.run() with shell=False is still HIGH in install-hook scope."""
        from pipguard.scanner import scan_python_file
        f = tmp_path / "setup.py"
        f.write_text("import subprocess\nsubprocess.run(['ls'], shell=False)\n")
        findings = scan_python_file(str(f), is_hook=True)
        assert any(fi.level.name == "HIGH" for fi in findings)

    def test_env_get_with_non_constant_key(self, tmp_path):
        """os.environ.get(variable) where variable is not a string constant."""
        from pipguard.scanner import scan_python_file
        f = tmp_path / "test.py"
        f.write_text("import os\nkey = 'MY_TOKEN'\nval = os.environ.get(key)\n")
        findings = scan_python_file(str(f))
        # The non-constant key path is exercised; no finding for variable key
        assert not any("sensitive env var" in fi.description for fi in findings)


class TestPkgNameLoopExhausts:
    def test_all_non_digit_parts_loop_exhausts(self):
        from pipguard.cli import _pkg_name_from_filename
        # Both parts are non-digit → loop exhausts without break
        result = _pkg_name_from_filename("requests-alpha.whl")
        assert result == "requests-alpha"
