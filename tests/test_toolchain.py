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
    LIVE_TEST_HOSTS,
    filter_system_store,
    live_check,
    mitigation_env,
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


def test_fingerprint_tables_are_well_formed():
    from pipguard.toolchain import COMPROMISED_TLS_INTERMEDIATES
    for fp in [*COMPROMISED_ROOTS, *COMPROMISED_TLS_INTERMEDIATES]:
        assert re.fullmatch(r"[0-9a-f]{64}", fp), fp
    assert len(COMPROMISED_TLS_INTERMEDIATES) == 12   # 6 TLS CAs x 2 issuers


def test_fixed_pip_requirement_is_hash_pinned():
    assert "pip-26.2.2-py3-none-any.whl" in FIXED_PIP_REQUIREMENT
    assert "#sha256=fd7f4dfa8190e014013b9f08f3e973f4e4c26ffd179a204895533a7254813a70" in FIXED_PIP_REQUIREMENT


# ── probe against a fake pip on PYTHONPATH ───────────────────────────────────

def _hide_os_store(tmp_path, monkeypatch):
    """Keep the developer's real macOS keychain out of probe tests: with an
    empty PATH the probe can't run `security`. (Linux has no OS store.)"""
    bin_dir = tmp_path / "empty-bin"
    bin_dir.mkdir(exist_ok=True)
    monkeypatch.setenv("PATH", str(bin_dir))


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
    monkeypatch.delenv("PIP_USE_DEPRECATED", raising=False)
    _hide_os_store(tmp_path, monkeypatch)
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
    _hide_os_store(tmp_path, monkeypatch)
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
    "platform,pip_hits,system_hits,os_hits,legacy,blocking",
    [
        ("linux", [G3], [], [], False, True),
        ("darwin", [G3], [], [], True, True),    # legacy-certs can't fix pip's own bundle
        ("win32", [G3], [], [], False, True),
        ("linux", [], [G3], [], False, True),    # pip's truststore reads this very file
        ("darwin", [], [G3], [], False, False),  # pip doesn't use the OpenSSL file here
        ("darwin", [], [], [G3], False, True),   # ...but it does ask the keychain
        ("darwin", [], [], [G3], True, False),   # unless it runs with legacy-certs
        ("win32", [], [], [G3], False, True),
        ("win32", [], [], [G3], True, False),
        ("linux", [], [], [], False, False),
    ],
)
def test_blocking_rules(platform, pip_hits, system_hits, os_hits, legacy, blocking):
    s = ToolchainStatus(executable="py", platform=platform, pip_version="26.2.2",
                        pip_hits=pip_hits, system_hits=system_hits, os_hits=os_hits,
                        legacy_certs=legacy)
    assert s.blocking is blocking


@pytest.mark.parametrize(
    "pip_version,pip_hits,expect_legacy",
    [("26.2.2", [], True), ("24.2", [], True), ("24.1.2", [], False), ("26.2.1", [G3], False)],
)
def test_mitigation_env_uses_legacy_certs_against_os_store(tmp_path, monkeypatch,
                                                          pip_version, pip_hits, expect_legacy):
    monkeypatch.setenv("PIP_USE_DEPRECATED", "some-other")
    s = ToolchainStatus(executable="py", platform="darwin", pip_version=pip_version,
                        pip_hits=pip_hits, os_store="macOS system keychain", os_hits=[G3])
    env = mitigation_env(s, str(tmp_path))
    if expect_legacy:
        assert env["PIP_USE_DEPRECATED"] == "some-other legacy-certs"
    else:
        assert "PIP_USE_DEPRECATED" not in env


@pytest.mark.real_toolchain
def test_probe_reads_legacy_certs_from_env(tmp_path, monkeypatch):
    _fake_env(tmp_path, monkeypatch, CLEAN_PEM, CLEAN_PEM, pip_version="26.2.2")
    assert probe_toolchain().legacy_certs is False
    monkeypatch.setenv("PIP_USE_DEPRECATED", "foo,legacy-certs")
    assert probe_toolchain().legacy_certs is True


@pytest.mark.parametrize(
    "output,expected",
    [
        ("ERROR: Could not find a version that satisfies the requirement x (from versions: none)", "ACCEPTED"),
        ("There was a problem confirming the ssl certificate: [SSL: CERTIFICATE_VERIFY_FAILED] "
         "certificate verify failed ... (from versions: none)", "rejected"),
        ("Failed to establish a new connection: Name or service not known", "unknown"),
    ],
)
def test_live_check_classifies_pip_output(output, expected):
    fake = types.SimpleNamespace(stdout="", stderr=output, returncode=1)
    with patch("pipguard.toolchain.subprocess.run", return_value=fake) as run:
        res = live_check("py", {"SSL_CERT_FILE": "/f.pem"})
    assert res == {h: expected for h in LIVE_TEST_HOSTS}
    cmd = run.call_args[0][0]
    assert "--index-url" in cmd and cmd[cmd.index("--index-url") + 1].startswith("https://")
    assert run.call_args[1]["env"]["SSL_CERT_FILE"] == "/f.pem"


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


def test_install_continues_when_only_unused_openssl_file_is_dirty():
    # macOS: pip asks the keychain, not the OpenSSL file, so this can't hurt pip.
    s = ToolchainStatus(executable="py", platform="darwin", pip_version="26.2.2",
                        system_stores=["/nonexistent.pem"], system_hits=[G3])
    with patch("pipguard.cli.probe_toolchain", return_value=s), \
         patch("pipguard.cli.download_packages", side_effect=RuntimeError("stop")) as dl:
        cmd_install(_install_args())
    dl.assert_called_once()


def test_install_switches_pip_to_legacy_certs_for_dirty_keychain(capsys, _restore_ssl_env, monkeypatch):
    monkeypatch.delenv("PIP_USE_DEPRECATED", raising=False)
    dirty = ToolchainStatus(executable="py", platform="darwin", pip_version="26.2.2",
                            os_store="macOS system keychain", os_hits=[G3])
    after = ToolchainStatus(executable="py", platform="darwin", pip_version="26.2.2",
                            os_store="macOS system keychain", os_hits=[G3], legacy_certs=True)
    with patch("pipguard.cli.probe_toolchain", side_effect=[dirty, after]), \
         patch("pipguard.cli.download_packages", side_effect=RuntimeError("stop")) as dl:
        cmd_install(_install_args())
    dl.assert_called_once()
    import os
    assert os.environ["PIP_USE_DEPRECATED"] == "legacy-certs"
    assert "PIP_USE_DEPRECATED=legacy-certs" in capsys.readouterr().err


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
    assert "filtered them out of the OpenSSL store" in capsys.readouterr().err


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

def _doctor(statuses, pythons=None, online=False):
    args = types.SimpleNamespace(python=pythons, online=online)
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


def test_doctor_online_reports_accepted_as_failure(capsys, tmp_path):
    ok_offline = ToolchainStatus(executable="py", python="3.12.0", pip_version="26.2.2")
    with patch("pipguard.cli.live_check",
               return_value={LIVE_TEST_HOSTS[0]: "ACCEPTED", LIVE_TEST_HOSTS[1]: "rejected"}):
        assert _doctor([ok_offline], online=True) == 1
    out = capsys.readouterr().out
    assert f"❌ plain pip → {LIVE_TEST_HOSTS[0]}: ACCEPTED" in out


def test_doctor_online_checks_mitigated_pip_too(capsys):
    keychain = ToolchainStatus(executable="py", python="3.12.0", platform="darwin",
                               pip_version="26.2.2", os_store="macOS system keychain", os_hits=[G3])
    calls = []

    def fake_live(exe, env):
        calls.append(env)
        verdict = "rejected" if env.get("PIP_USE_DEPRECATED") else "ACCEPTED"
        return {h: verdict for h in LIVE_TEST_HOSTS}

    with patch("pipguard.cli.live_check", side_effect=fake_live):
        assert _doctor([keychain], online=True) == 1
    assert calls[0] == {} and calls[1]["PIP_USE_DEPRECATED"].endswith("legacy-certs")
    assert "✅ pip under pipguard" in capsys.readouterr().out


def test_doctor_parses_multiple_pythons():
    args = build_parser().parse_args(["doctor", "--python", "a", "--python", "b"])
    assert args.python == ["a", "b"]
