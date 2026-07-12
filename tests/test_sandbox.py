"""Tests for the experimental capability sandbox prototype (#55)."""

import os
import sys

from pipguard.sandbox import (
    DEFAULT_DENY_FRAGMENTS,
    make_sitecustomize,
    path_is_denied,
    run_sandboxed,
)


# ── path_is_denied ───────────────────────────────────────────────────────────

def test_path_is_denied_matches_credential_paths():
    assert path_is_denied("/home/u/.ssh/id_rsa", ["/.ssh/"])
    assert path_is_denied("~/.aws/credentials", ["/.aws/"])


def test_path_is_denied_expands_user():
    home_ssh = os.path.join(os.path.expanduser("~"), ".ssh", "id_ed25519")
    assert path_is_denied(home_ssh, DEFAULT_DENY_FRAGMENTS)


def test_path_is_denied_allows_normal_paths():
    assert not path_is_denied("/tmp/data.txt", ["/.ssh/"])
    assert not path_is_denied("", ["/.ssh/"])


def test_path_is_denied_handles_resolution_error_safely():
    # If path normalisation raises, treat the path as not denied (fail open on
    # the matcher; the sandbox hook has its own guard).
    from unittest.mock import patch
    with patch("os.path.abspath", side_effect=ValueError("bad path")):
        assert not path_is_denied("/home/u/.ssh/id_rsa", ["/.ssh/"])


def test_make_sitecustomize_bakes_policy():
    src = make_sitecustomize(["/.ssh/"], allow_network=False, allow_subprocess=True)
    assert "addaudithook" in src
    assert "/.ssh/" in src
    assert "_ALLOW_NET = False" in src
    assert "_ALLOW_SUB = True" in src


# ── run_sandboxed (real subprocess, hermetic) ────────────────────────────────

def test_sandbox_blocks_credential_read(tmp_path):
    ssh_dir = tmp_path / ".ssh"
    ssh_dir.mkdir()
    key = ssh_dir / "id_rsa"
    key.write_text("PRIVATE KEY")
    rc = run_sandboxed(
        [sys.executable, "-c", f"open({str(key)!r}).read()"],
        deny_fragments=["/.ssh/"],
        timeout=30,
    )
    assert rc != 0, "reading a credential path must be blocked"


def test_sandbox_allows_normal_read(tmp_path):
    f = tmp_path / "data.txt"
    f.write_text("hello")
    rc = run_sandboxed(
        [sys.executable, "-c", f"open({str(f)!r}).read()"],
        deny_fragments=["/.ssh/"],
        timeout=30,
    )
    assert rc == 0, "reading a normal file must be allowed"


def test_sandbox_blocks_outbound_network():
    # socket.connect fires the audit event before the syscall, so this is
    # hermetic — no real network is required for the block to trigger.
    rc = run_sandboxed(
        [sys.executable, "-c",
         "import socket; socket.create_connection(('1.1.1.1', 80), timeout=2)"],
        allow_network=False,
        timeout=30,
    )
    assert rc != 0, "outbound network must be blocked when allow_network=False"


def test_sandbox_blocks_subprocess_when_disallowed():
    rc = run_sandboxed(
        [sys.executable, "-c",
         "import subprocess; subprocess.Popen(['echo', 'hi'])"],
        allow_subprocess=False,
        timeout=30,
    )
    assert rc != 0, "process execution must be blocked when allow_subprocess=False"


def test_sandbox_allows_subprocess_by_default(tmp_path):
    # A benign command with the default allow_subprocess=True should succeed.
    rc = run_sandboxed(
        [sys.executable, "-c", "print('ok')"],
        deny_fragments=["/.ssh/"],
        timeout=30,
    )
    assert rc == 0


def test_sandbox_capture_output_writes_through_on_failure(capsys):
    """capture_output=True surfaces the child's stdout/stderr on a non-zero exit."""
    code = "import sys; sys.stdout.write('OUT'); sys.stderr.write('ERR'); sys.exit(3)"
    rc = run_sandboxed(
        [sys.executable, "-c", code],
        deny_fragments=["/.ssh/"],
        capture_output=True,
        timeout=30,
    )
    assert rc == 3
    out = capsys.readouterr()
    assert "OUT" in out.out
    assert "ERR" in out.err


def test_sandbox_capture_output_failure_without_output(capsys):
    """capture_output=True with a non-zero exit but no stdout/stderr must not
    write anything (covers the empty-output branches)."""
    rc = run_sandboxed(
        [sys.executable, "-c", "import sys; sys.exit(2)"],
        deny_fragments=["/.ssh/"],
        capture_output=True,
        timeout=30,
    )
    assert rc == 2
    out = capsys.readouterr()
    assert out.out == ""
    assert out.err == ""


def test_sandbox_does_not_break_offline_pip_install(tmp_path):
    """Integration: pip installs a wheel offline UNDER the sandbox (rc 0),
    proving the sandbox permits pip's own legitimate file access.

    Installs into an isolated --target that is never added to sys.path, so the
    fixture's .pth payload is written but never executed.
    """
    wheels = os.path.join(os.path.dirname(__file__), "fixtures", "wheels")
    if not os.path.isdir(wheels) or not os.listdir(wheels):
        import pytest
        pytest.skip("no fixture wheels available")
    target = tmp_path / "target"
    cmd = [
        sys.executable, "-m", "pip", "install", "--no-index", "--no-deps",
        "--find-links", wheels, "--target", str(target), "malicious-pth",
    ]
    rc = run_sandboxed(cmd, allow_network=False, allow_subprocess=True, timeout=120)
    assert rc == 0
