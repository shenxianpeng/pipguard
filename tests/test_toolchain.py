"""Tests for the compromised-CA toolchain check (eMudhra / emSign, Oct 2026)."""

import base64
import hashlib
import re
import sys
import types
from pathlib import Path
from unittest.mock import patch

import pytest

from pipguard import toolchain
from pipguard.cli import _toolchain_gate, build_parser, cmd_doctor, cmd_install
from pipguard.toolchain import (
    COMPROMISED_ROOTS,
    FIXED_PIP_REQUIREMENT,
    ToolchainStatus,
    describe,
    filter_system_store,
    probe_toolchain,
)

CERTS = Path(__file__).parent / "fixtures" / "certs"
G3_PEM = (CERTS / "emsign_ecc_root_ca_g3.pem").read_text()
CLEAN_PEM = (CERTS / "isrg_root_x1.pem").read_text()
G3 = "86a1ecba089c4a8d3bbe2734c612ba341d813e043cf9e8a862cd5c57a36bbe6b"


def _sha256_of_pem(pem: str) -> str:
    body = re.search(r"-----BEGIN CERTIFICATE-----(.*?)-----END", pem, re.S).group(1)
    return hashlib.sha256(base64.b64decode("".join(body.split()))).hexdigest()


def test_fixture_is_the_compromised_root():
    # Guards the hard-coded fingerprint against typos.
    assert _sha256_of_pem(G3_PEM) == G3
    assert G3 in COMPROMISED_ROOTS
    assert _sha256_of_pem(CLEAN_PEM) not in COMPROMISED_ROOTS


def test_fixed_pip_requirement_is_hash_pinned():
    assert "pip-26.2.2-py3-none-any.whl" in FIXED_PIP_REQUIREMENT
    assert "#sha256=fd7f4dfa8190e014013b9f08f3e973f4e4c26ffd179a204895533a7254813a70" in FIXED_PIP_REQUIREMENT


# ── probe against a fake pip on PYTHONPATH ───────────────────────────────────

def _fake_env(tmp_path, monkeypatch, pip_bundle_pem, system_pem, pip_version="26.2.1"):
    """Put a fake `pip` (with its own certifi bundle) first on sys.path and
    point the OpenSSL default store at our own file."""
    bundle = tmp_path / "pip_cacert.pem"
    bundle.write_text(pip_bundle_pem)
    pkg = tmp_path / "site" / "pip"
    (pkg / "_vendor" / "certifi").mkdir(parents=True)
    (pkg / "__init__.py").write_text(f"__version__ = {pip_version!r}\n")
    (pkg / "_vendor" / "__init__.py").write_text("")
    (pkg / "_vendor" / "certifi" / "__init__.py").write_text(
        f"def where():\n    return {str(bundle)!r}\n"
    )
    system = tmp_path / "system.pem"
    system.write_text(system_pem)
    empty_dir = tmp_path / "certs"
    empty_dir.mkdir()
    monkeypatch.setenv("PYTHONPATH", str(tmp_path / "site"))
    monkeypatch.setenv("SSL_CERT_FILE", str(system))
    monkeypatch.setenv("SSL_CERT_DIR", str(empty_dir))
    return bundle, system


@pytest.mark.real_toolchain
def test_probe_flags_vendored_bundle_with_compromised_root(tmp_path, monkeypatch):
    bundle, _ = _fake_env(tmp_path, monkeypatch, CLEAN_PEM + G3_PEM, CLEAN_PEM)
    status = probe_toolchain()
    assert status.pip_version == "26.2.1"
    assert status.pip_bundle == str(bundle)
    assert status.pip_hits == [G3]
    assert status.system_hits == []
    assert status.blocking


@pytest.mark.real_toolchain
def test_probe_clean_bundle_is_trusted_even_on_old_pip(tmp_path, monkeypatch):
    # e.g. Debian patches pip to use the (updated) system store.
    _fake_env(tmp_path, monkeypatch, CLEAN_PEM, CLEAN_PEM, pip_version="23.0.1")
    status = probe_toolchain()
    assert status.checked
    assert not status.compromised
    assert not status.blocking


@pytest.mark.real_toolchain
def test_probe_flags_system_store(tmp_path, monkeypatch):
    _, system = _fake_env(tmp_path, monkeypatch, CLEAN_PEM, G3_PEM)
    status = probe_toolchain()
    assert status.pip_hits == []
    assert status.system_hits == [G3]
    assert str(system) in status.system_stores
    assert status.blocking == sys.platform.startswith("linux")


@pytest.mark.real_toolchain
def test_probe_without_pip(tmp_path, monkeypatch):
    pkg = tmp_path / "site" / "pip"
    pkg.mkdir(parents=True)
    (pkg / "__init__.py").write_text("raise ImportError('no pip here')\n")
    monkeypatch.setenv("PYTHONPATH", str(tmp_path / "site"))
    clean = tmp_path / "clean.pem"
    clean.write_text(CLEAN_PEM)
    monkeypatch.setenv("SSL_CERT_FILE", str(clean))
    monkeypatch.setenv("SSL_CERT_DIR", str(tmp_path))
    status = probe_toolchain()
    assert not status.checked
    assert "no pip here" in status.error
    assert not status.blocking


def test_probe_bad_interpreter():
    status = probe_toolchain("/nonexistent/python")
    assert not status.checked
    assert status.error


# ── blocking rules and messages ──────────────────────────────────────────────

@pytest.mark.parametrize(
    "platform,pip_hits,system_hits,blocking",
    [
        ("linux", [G3], [], True),
        ("darwin", [G3], [], True),
        ("win32", [G3], [], True),
        ("linux", [], [G3], True),     # pip's truststore reads this very file
        ("darwin", [], [G3], False),   # pip asks the OS; warn only
        ("win32", [], [G3], False),
        ("linux", [], [], False),
    ],
)
def test_blocking_rules(platform, pip_hits, system_hits, blocking):
    s = ToolchainStatus(executable="py", platform=platform, pip_version="1",
                        pip_hits=pip_hits, system_hits=system_hits)
    assert s.blocking is blocking


def test_describe_gives_hash_pinned_fix():
    s = ToolchainStatus(executable="/venv/bin/python", python="3.12.1", platform="linux",
                        pip_version="26.2.1", pip_bundle="/b.pem", pip_hits=[G3])
    text = "\n".join(describe(s))
    assert "emSign ECC Root CA - G3" in text
    assert f'/venv/bin/python -m pip install "{FIXED_PIP_REQUIREMENT}"' in text
    assert toolchain.INCIDENT_URL in text


def test_describe_old_python_cannot_take_fixed_pip():
    s = ToolchainStatus(executable="py39", python="3.9.6", platform="darwin",
                        pip_version="25.3", pip_hits=[G3])
    text = "\n".join(describe(s))
    assert "needs Python 3.10+" in text
    assert FIXED_PIP_REQUIREMENT not in text


def test_describe_clean_is_empty():
    assert describe(ToolchainStatus(executable="py", pip_version="26.2.2")) == []


# ── CLI gate ─────────────────────────────────────────────────────────────────

BAD = ToolchainStatus(executable="py", python="3.12.0", platform="linux",
                      pip_version="26.2.1", pip_bundle="/b.pem", pip_hits=[G3])


def _install_args(**kw):
    args = build_parser().parse_args(["install", "requests", "--yes"])
    for k, v in kw.items():
        setattr(args, k, v)
    return args


def test_install_blocks_before_download_when_pip_untrusted(capsys):
    with patch("pipguard.cli.probe_toolchain", return_value=BAD), \
         patch("pipguard.cli.download_packages") as dl:
        rc = cmd_install(_install_args())
    assert rc == 2
    dl.assert_not_called()
    err = capsys.readouterr().err
    assert "Untrusted TLS toolchain" in err
    assert FIXED_PIP_REQUIREMENT in err


def test_install_with_require_hashes_only_warns(capsys):
    with patch("pipguard.cli.probe_toolchain", return_value=BAD), \
         patch("pipguard.cli.download_packages", side_effect=RuntimeError("stop")) as dl:
        rc = cmd_install(_install_args(require_hashes=True))
    dl.assert_called_once()          # got past the gate
    assert rc == 2                   # from our stubbed download error
    assert "--require-hashes lets pip verify" in capsys.readouterr().err


def test_install_skip_flag_bypasses_probe():
    with patch("pipguard.cli.probe_toolchain") as probe, \
         patch("pipguard.cli.download_packages", side_effect=RuntimeError("stop")) as dl:
        cmd_install(_install_args(skip_toolchain_check=True))
    probe.assert_not_called()
    dl.assert_called_once()


def test_install_warns_when_macos_system_store_cannot_be_filtered(capsys):
    warn_only = ToolchainStatus(executable="py", platform="darwin", pip_version="26.2.2",
                                system_stores=["/nonexistent.pem"], system_hits=[G3])
    with patch("pipguard.cli.probe_toolchain", return_value=warn_only), \
         patch("pipguard.cli.download_packages", side_effect=RuntimeError("stop")) as dl:
        cmd_install(_install_args())
    dl.assert_called_once()
    assert "⚠️" in capsys.readouterr().err


# ── system store mitigation (GitHub's ubuntu runners still ship the root) ────

@pytest.fixture
def _restore_ssl_env(monkeypatch):
    # The gate exports SSL_CERT_FILE/DIR into os.environ; undo it after a test.
    monkeypatch.setenv("SSL_CERT_FILE", "")
    monkeypatch.setenv("SSL_CERT_DIR", "")
    monkeypatch.delenv("SSL_CERT_FILE")
    monkeypatch.delenv("SSL_CERT_DIR")


def test_filter_system_store_drops_compromised_root(tmp_path):
    store = tmp_path / "cert.pem"
    store.write_text(CLEAN_PEM + G3_PEM)
    certdir = tmp_path / "certs"
    certdir.mkdir()
    (certdir / "aaaa.0").write_text(G3_PEM)
    (certdir / "bbbb.0").write_text(CLEAN_PEM)          # duplicate, kept once
    status = ToolchainStatus(executable="py", platform="linux", pip_version="26.2.2",
                             system_stores=[str(store), str(certdir), "windows:ROOT"],
                             system_hits=[G3])
    env = filter_system_store(status, str(tmp_path / "work"))
    bundle = Path(env["SSL_CERT_FILE"]).read_text()
    assert [_sha256_of_pem(b) for b in re.findall(r"-----BEGIN.*?-----END CERTIFICATE-----", bundle, re.S)] == [
        _sha256_of_pem(CLEAN_PEM)
    ]
    assert Path(env["SSL_CERT_DIR"]).is_dir()
    assert list(Path(env["SSL_CERT_DIR"]).iterdir()) == []


def test_filter_system_store_noop_without_hits(tmp_path):
    status = ToolchainStatus(executable="py", system_stores=["/x.pem"], system_hits=[])
    assert filter_system_store(status, str(tmp_path)) == {}


@pytest.mark.real_toolchain
def test_gate_neutralises_dirty_system_store_end_to_end(tmp_path, monkeypatch, capsys):
    # pip itself is clean (26.2.2), but the OpenSSL store still has the root —
    # exactly the state of GitHub's ubuntu runners in Oct 2026.
    _, system = _fake_env(tmp_path, monkeypatch, CLEAN_PEM, CLEAN_PEM + G3_PEM,
                          pip_version="26.2.2")
    assert probe_toolchain().system_hits == [G3]

    assert _toolchain_gate(require_hashes=False) == 0

    import os
    assert os.environ["SSL_CERT_FILE"] != str(system)
    after = probe_toolchain()                      # what pip will see now
    assert not after.compromised
    assert "removed it for this run" in capsys.readouterr().err


@pytest.mark.real_toolchain
def test_gate_still_blocks_old_pip_with_dirty_system_store(tmp_path, monkeypatch):
    # Filtering the system store can't help: old pip always loads its own bundle.
    _fake_env(tmp_path, monkeypatch, CLEAN_PEM + G3_PEM, CLEAN_PEM + G3_PEM, pip_version="26.2.1")
    assert _toolchain_gate(require_hashes=False) == 2
    assert not probe_toolchain().system_hits      # store was filtered...
    assert probe_toolchain().pip_hits == [G3]     # ...pip's bundle was not


def test_install_proceeds_after_linux_store_is_filtered(tmp_path, _restore_ssl_env):
    store = tmp_path / "cert.pem"
    store.write_text(CLEAN_PEM + G3_PEM)
    dirty = ToolchainStatus(executable="py", platform="linux", pip_version="26.2.2",
                            system_stores=[str(store)], system_hits=[G3])
    clean = ToolchainStatus(executable="py", platform="linux", pip_version="26.2.2")
    with patch("pipguard.cli.probe_toolchain", side_effect=[dirty, clean]), \
         patch("pipguard.cli.download_packages", side_effect=RuntimeError("stop")) as dl:
        cmd_install(_install_args())
    dl.assert_called_once()


def test_skip_flag_parses():
    args = build_parser().parse_args(["install", "x", "--skip-toolchain-check"])
    assert args.skip_toolchain_check is True


# ── doctor ───────────────────────────────────────────────────────────────────

def _doctor(statuses, pythons=None):
    args = types.SimpleNamespace(python=pythons)
    it = iter(statuses)
    with patch("pipguard.cli.probe_toolchain", side_effect=lambda *a, **k: next(it)):
        return cmd_doctor(args)


def test_doctor_clean(capsys):
    ok = ToolchainStatus(executable="py", python="3.12.0", pip_version="26.2.2")
    assert _doctor([ok]) == 0
    assert "✅" in capsys.readouterr().out


def test_doctor_reports_blocking(capsys):
    assert _doctor([BAD]) == 1
    out = capsys.readouterr().out
    assert "❌" in out and FIXED_PIP_REQUIREMENT in out


def test_doctor_unreadable_interpreter(capsys):
    assert _doctor([ToolchainStatus(executable="x", error="boom")], ["x"]) == 2


def test_doctor_parses_multiple_pythons():
    args = build_parser().parse_args(["doctor", "--python", "a", "--python", "b"])
    assert args.python == ["a", "b"]
