"""Shared fixtures."""

import pytest

from pipguard.toolchain import ToolchainStatus


@pytest.fixture(autouse=True)
def _trusted_toolchain(request, monkeypatch):
    """Keep CLI tests independent of the runner's real pip / CA stores.

    Tests that exercise the toolchain gate itself opt out with
    ``@pytest.mark.real_toolchain`` or patch ``probe_toolchain`` themselves.
    """
    if request.node.get_closest_marker("real_toolchain"):
        return
    monkeypatch.setattr(
        "pipguard.cli.probe_toolchain",
        lambda *a, **k: ToolchainStatus(
            executable="python", python="3.12.0", platform="linux", pip_version="26.2.2"
        ),
    )


def pytest_configure(config):
    config.addinivalue_line(
        "markers", "real_toolchain: don't stub the pip/CA toolchain probe"
    )
