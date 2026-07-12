"""Tests for install_from_local, including the --sandbox path (#55)."""

import os
import sys
from unittest.mock import patch

from pipguard.installer import install_from_local

FIXTURE_WHEELS = os.path.join(os.path.dirname(__file__), "fixtures", "wheels")


def test_sandbox_routes_through_run_sandboxed():
    with patch("pipguard.installer.run_sandboxed", return_value=0) as mock_run:
        rc = install_from_local(["pkg"], "/tmp/links", sandbox=True)
    assert rc == 0
    mock_run.assert_called_once()
    kwargs = mock_run.call_args.kwargs
    # network denied (offline --no-index install), subprocesses allowed
    assert kwargs["allow_network"] is False
    assert kwargs["allow_subprocess"] is True


def test_non_sandbox_uses_plain_subprocess():
    with patch("pipguard.installer.subprocess.run") as mock_sub, \
         patch("pipguard.installer.run_sandboxed") as mock_run:
        mock_sub.return_value.returncode = 0
        install_from_local(["pkg"], "/tmp/links", sandbox=False, show_pip_output=True)
    mock_run.assert_not_called()
    mock_sub.assert_called_once()


def test_sandbox_capture_output_flag_passed():
    """Quiet default (show_pip_output=False) → sandbox captures output."""
    with patch("pipguard.installer.run_sandboxed", return_value=0) as mock_run:
        install_from_local(["pkg"], "/tmp/links", sandbox=True, show_pip_output=False)
    assert mock_run.call_args.kwargs["capture_output"] is True

    with patch("pipguard.installer.run_sandboxed", return_value=0) as mock_run:
        install_from_local(["pkg"], "/tmp/links", sandbox=True, show_pip_output=True)
    assert mock_run.call_args.kwargs["capture_output"] is False
