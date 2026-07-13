"""Tests for the resilient scan-feed downloader (download_for_scan)."""

import types
from unittest.mock import patch

from pipguard.downloader import download_for_scan


def _ok(*a, **k):
    return types.SimpleNamespace(returncode=0, stdout="", stderr="")


def test_download_for_scan_skips_failures_and_collects_rest(tmp_path):
    # Two artifacts "already downloaded"; a third spec fails.
    (tmp_path / "a-1.0-py3-none-any.whl").write_text("")
    (tmp_path / "b-2.0.tar.gz").write_text("")

    def fake_run(cmd, **kwargs):
        rc = 1 if any("bad" in part for part in cmd) else 0
        return types.SimpleNamespace(returncode=rc, stdout="", stderr="boom")

    with patch("pipguard.downloader.subprocess.run", side_effect=fake_run):
        archives, skipped = download_for_scan(
            ["a==1.0", "b==2.0", "bad==9.9"], str(tmp_path)
        )

    assert skipped == ["bad==9.9"]
    assert len(archives) == 2
    assert any(a.endswith(".whl") for a in archives)
    assert any(a.endswith(".tar.gz") for a in archives)  # sdists are kept


def test_download_for_scan_is_per_spec(tmp_path):
    calls = []

    def fake_run(cmd, **kwargs):
        calls.append(cmd)
        return types.SimpleNamespace(returncode=0, stdout="", stderr="")

    with patch("pipguard.downloader.subprocess.run", side_effect=fake_run):
        download_for_scan(["x==1", "y==2", "z==3"], str(tmp_path))

    assert len(calls) == 3  # one pip invocation per spec (resilient, not batched)


def test_download_for_scan_uses_no_deps_and_ignore_requires_python(tmp_path):
    with patch("pipguard.downloader.subprocess.run", side_effect=_ok) as mock_run:
        download_for_scan(["x==1"], str(tmp_path))
    cmd = mock_run.call_args[0][0]
    assert "--no-deps" in cmd
    assert "--ignore-requires-python" in cmd
    assert "download" in cmd
