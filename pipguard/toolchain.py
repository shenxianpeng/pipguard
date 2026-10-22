"""Check that the pip pipguard drives does not trust the compromised eMudhra CAs.

pipguard downloads packages with ``python -m pip download``. If that pip trusts
a certificate authority whose key has leaked, anyone on the network path can
forge a certificate for pypi.org / files.pythonhosted.org and swap the bytes
pipguard is about to scan and install.

This happened in October 2026: the private keys of eight eMudhra intermediate
CAs were trivially weak (https://emudhra.we-have-a-problem.com/). They chain to:

* "emSign ECC Root CA - G3" (Mozilla/certifi, Apple, Microsoft) — removed in
  certifi 2026.10.18/19 and pip 26.2.2. Every older pip always loads its
  vendored certifi, so updating the OS alone does not help.
* "emSign Root TLS CA - G3" (Microsoft only) and Sectigo's "AAA Certificate
  Services" (Apple, Microsoft; already removed by Mozilla and Chrome).

pip 24.2+ also asks the system trust store (truststore). So pip trusts the bad
intermediates if *any* of these holds, and pipguard handles each one:

* root in pip's own CA bundle → block; only upgrading pip helps.
* root in the OpenSSL system store (what truststore reads on Linux) → filter
  it out for the run via ``SSL_CERT_FILE``.
* root in the OS store (macOS keychain, Windows) → run pip with
  ``legacy-certs`` so it uses only its own, now clean, bundle.

The checks look at certificates, not version numbers, so distro-patched pips
(e.g. Debian's, which use the updated system store) are not flagged.
"""

from __future__ import annotations

import base64
import hashlib
import json
import os
import re
import subprocess
import sys
import tempfile
from dataclasses import dataclass, field
from typing import Dict, List, Optional, Tuple

# Roots that make the compromised intermediates trusted. SHA-256 of the DER
# certificate (lower-case hex) → name. Source: roots.json on the incident site.
COMPROMISED_ROOTS: Dict[str, str] = {
    "86a1ecba089c4a8d3bbe2734c612ba341d813e043cf9e8a862cd5c57a36bbe6b": "emSign ECC Root CA - G3",
    "7dd78d5f4f13459a83dff9abbba62edbaf6f2d102bf257fd712f4d9f2746ed8d": "emSign Root TLS CA - G3",
    "d7a7a0fb5d7e2731d771e9484ebcdef71d5f0c3e0a2948782bc83ee0ea699ef4": "AAA Certificate Services (Sectigo)",
}

# The compromised TLS intermediates themselves (both issuers of each). Windows
# distrusts them through its "Disallowed" store; if every one is there, the
# Windows verifier already rejects them. Source: impacted-intermediates.json.
COMPROMISED_TLS_INTERMEDIATES = frozenset({
    "42c4accd12c4f59597925e1a08a7a90102608543809308d50ec427e118ba1493",
    "45a883f349aedfd5f3a649b5498ffb121712ba8b448f3f2a91dbc5a766fcddbe",
    "98b896625c0c230adeec3eb2cf6aad5001ecf9156a68644e82374ce5833bc25b",
    "5f1ded4dd590af74631290cf073b122a2aac6a1fa479778a0bd43579bd832699",
    "e7568fe6e12331f4fd7de61da4c7559d0f8eb192a218d4741a3ba75184333838",
    "579480aea166290bd3c643589e795fc0d0e54e86505d180f1dff99efd3199512",
    "0164d7ceae5bb909c272af151ff44b1177ae9b47d9424b94f1d9558c30934d19",
    "62b7f9868263f72f6911fc78ceaf72c1979158b7368bf648683bb2aa39b02e72",
    "cb6e15165ac802e9b3f993f16c25d41f4e81c21ebde71ae1b012ac00bf9c7c3f",
    "7485b51c0ed192878fa1d2f948fb529ae1842cc5086c4b67f7be5b2039de9489",
    "432ec25f0d28de9006d97bf752f17bbb2cd41f669933fcb072d9a1148d0261f3",
    "fd9d5c2dbbd4995ab69b8d50c439d9527b00529199c2fd01b2174eb58f07021f",
})

INCIDENT_URL = (
    "https://discuss.python.org/t/information-for-python-users-regarding-"
    "emudhra-emsign-ca-certificate-security-incident/109576"
)

# Hosts the incident reporters run with certificates from the compromised
# intermediates (one per root path). A client that completes a TLS handshake
# with them trusts the compromised CAs.
LIVE_TEST_HOSTS = (
    "dv-g3b-emudhra.we-have-a-problem.com",
    "dv-g3b-aaa-emudhra.we-have-a-problem.com",
)

# First pip release whose vendored certifi drops the compromised root.
FIXED_PIP_VERSION = "26.2.2"
FIXED_PIP_REQUIREMENT = (
    "pip @ https://files.pythonhosted.org/packages/3f/06/"
    "3e4420302363fbb71be3c7f35ce042f54bfca330e3e66b3a2e3c4cca579f/"
    "pip-26.2.2-py3-none-any.whl"
    "#sha256=fd7f4dfa8190e014013b9f08f3e973f4e4c26ffd179a204895533a7254813a70"
)

# Runs inside the target interpreter. Self-contained and written for old
# Pythons too (no f-strings), because `pipguard doctor --python` can point at
# any interpreter. It imports pip the same way `python -m pip` does and sees
# the same environment variables pip would.
_PROBE = r'''
import base64, hashlib, json, os, re, ssl, subprocess, sys
BAD = set(json.loads(sys.argv[1]))
INTERMEDIATES = set(json.loads(sys.argv[2]))
PEM = re.compile(r"-----BEGIN CERTIFICATE-----(.*?)-----END CERTIFICATE-----", re.S)

def fingerprints(path):
    try:
        with open(path, "rb") as fh:
            text = fh.read().decode("ascii", "replace")
    except (IOError, OSError):
        return None
    out = set()
    for m in PEM.finditer(text):
        try:
            der = base64.b64decode("".join(m.group(1).split()))
        except Exception:
            continue
        out.add(hashlib.sha256(der).hexdigest())
    return out

deprecated = os.environ.get("PIP_USE_DEPRECATED", "").replace(",", " ").split()
res = {"python": sys.version.split()[0], "executable": sys.executable,
       "platform": sys.platform, "pip_version": None, "pip_bundle": None,
       "pip_hits": [], "system_stores": [], "system_hits": [],
       "os_store": None, "os_hits": [], "error": None,
       "legacy_certs": "legacy-certs" in deprecated}
try:
    import pip
    res["pip_version"] = pip.__version__
    from pip._vendor import certifi
    res["pip_bundle"] = certifi.where()
    found = fingerprints(res["pip_bundle"])
    if found is not None:
        res["pip_hits"] = sorted(found & BAD)
except Exception as exc:
    res["error"] = "%s: %s" % (type(exc).__name__, exc)

# OpenSSL store; cafile/capath already honour SSL_CERT_FILE / SSL_CERT_DIR.
hits = set()
paths = ssl.get_default_verify_paths()
if paths.cafile and os.path.isfile(paths.cafile):
    found = fingerprints(paths.cafile)
    if found is not None:
        res["system_stores"].append(paths.cafile)
        hits |= found & BAD
if paths.capath and os.path.isdir(paths.capath):
    res["system_stores"].append(paths.capath)
    for name in os.listdir(paths.capath):
        p = os.path.join(paths.capath, name)
        if os.path.isfile(p):
            found = fingerprints(p)
            if found:
                hits |= found & BAD
res["system_hits"] = sorted(hits)

# OS verifier that pip's truststore uses on macOS / Windows.
os_hits = set()
if sys.platform == "darwin":
    res["os_store"] = "macOS system keychain"
    for kc in ("/System/Library/Keychains/SystemRootCertificates.keychain",
               "/Library/Keychains/System.keychain"):
        try:
            out = subprocess.Popen(["security", "find-certificate", "-a", "-Z", kc],
                                   stdout=subprocess.PIPE, stderr=subprocess.PIPE,
                                   universal_newlines=True).communicate()[0]
        except Exception:
            continue
        for m in re.finditer(r"SHA-256 hash:\s*([0-9A-Fa-f]{64})", out):
            if m.group(1).lower() in BAD:
                os_hits.add(m.group(1).lower())
elif hasattr(ssl, "enum_certificates"):
    res["os_store"] = "Windows certificate store"
    for store in ("ROOT", "CA"):
        try:
            for der, enc, _trust in ssl.enum_certificates(store):
                if enc == "x509_asn":
                    fp = hashlib.sha256(der).hexdigest()
                    if fp in BAD:
                        os_hits.add(fp)
        except Exception:
            pass
    try:
        disallowed = set(hashlib.sha256(der).hexdigest()
                         for der, enc, _t in ssl.enum_certificates("Disallowed")
                         if enc == "x509_asn")
    except Exception:
        disallowed = set()
    if INTERMEDIATES and INTERMEDIATES <= disallowed:
        os_hits = set()  # Windows already distrusts every compromised intermediate
res["os_hits"] = sorted(os_hits)
print(json.dumps(res))
'''


@dataclass
class ToolchainStatus:
    """What one interpreter's pip and TLS trust stores look like."""

    executable: str
    python: Optional[str] = None
    platform: str = ""
    pip_version: Optional[str] = None
    pip_bundle: Optional[str] = None
    pip_hits: List[str] = field(default_factory=list)
    system_stores: List[str] = field(default_factory=list)
    system_hits: List[str] = field(default_factory=list)
    os_store: Optional[str] = None
    os_hits: List[str] = field(default_factory=list)
    legacy_certs: bool = False
    error: Optional[str] = None

    @property
    def checked(self) -> bool:
        """False when pip could not be inspected at all."""
        return self.pip_version is not None

    @property
    def compromised(self) -> bool:
        """True if any trust store this interpreter can use contains a bad root."""
        return bool(self.pip_hits or self.system_hits or self.os_hits)

    @property
    def blocking(self) -> bool:
        """True if pip, run with the current environment, trusts a bad root.

        * pip's own bundle is always loaded.
        * On Linux pip's truststore reads the OpenSSL store we inspected.
        * On macOS/Windows truststore asks the OS store instead, unless pip
          runs with ``legacy-certs`` (own bundle only).
        """
        if self.pip_hits:
            return True
        if self.system_hits and self.platform.startswith("linux"):
            return True
        return bool(self.os_hits) and not self.legacy_certs


def probe_toolchain(python: Optional[str] = None, timeout: int = 60) -> ToolchainStatus:
    """Inspect the pip and trust stores of ``python`` (default: this interpreter).

    Runs with the current ``os.environ``, so overrides set from
    :func:`mitigation_env` are reflected exactly as pip would see them.
    """
    exe = python or sys.executable
    try:
        proc = subprocess.run(
            [exe, "-c", _PROBE, json.dumps(sorted(COMPROMISED_ROOTS)),
             json.dumps(sorted(COMPROMISED_TLS_INTERMEDIATES))],
            capture_output=True, text=True, timeout=timeout,
        )
    except (OSError, subprocess.TimeoutExpired) as exc:
        return ToolchainStatus(executable=exe, error=f"{type(exc).__name__}: {exc}")
    try:
        data = json.loads(proc.stdout.strip().splitlines()[-1])
    except (IndexError, ValueError):
        err = (proc.stderr or proc.stdout).strip().splitlines()
        return ToolchainStatus(executable=exe, error=err[-1] if err else "probe failed")
    return ToolchainStatus(
        executable=exe,
        python=data.get("python"),
        platform=data.get("platform") or "",
        pip_version=data.get("pip_version"),
        pip_bundle=data.get("pip_bundle"),
        pip_hits=list(data.get("pip_hits") or []),
        system_stores=list(data.get("system_stores") or []),
        system_hits=list(data.get("system_hits") or []),
        os_store=data.get("os_store"),
        os_hits=list(data.get("os_hits") or []),
        legacy_certs=bool(data.get("legacy_certs")),
        error=data.get("error"),
    )


# ── Mitigation ───────────────────────────────────────────────────────────────

_PEM_RE = re.compile(
    r"-----BEGIN CERTIFICATE-----.*?-----END CERTIFICATE-----", re.S
)


def _pem_blocks(path: str) -> List[str]:
    try:
        with open(path, "rb") as fh:
            text = fh.read().decode("ascii", "replace")
    except OSError:
        return []
    return _PEM_RE.findall(text)


def _fingerprint(pem: str) -> Optional[str]:
    body = pem.split("-----", 2)[2].rsplit("-----END", 1)[0]
    try:
        der = base64.b64decode("".join(body.split()))
    except ValueError:
        return None
    return hashlib.sha256(der).hexdigest()


def filter_system_store(status: ToolchainStatus, work_dir: str) -> Dict[str, str]:
    """Copy the OpenSSL system store without the compromised roots.

    Returns ``SSL_CERT_FILE`` / ``SSL_CERT_DIR`` overrides pointing at the
    filtered copy (empty dict if there is nothing to filter). OpenSSL, Python's
    ``ssl`` module and pip's truststore backend on Linux all honour them, and
    the rest of the store (e.g. a corporate CA) keeps working.
    """
    if not status.system_hits or not status.system_stores:
        return {}
    kept: Dict[str, str] = {}
    for src in status.system_stores:
        files = [src]
        if os.path.isdir(src):
            files = [os.path.join(src, n) for n in sorted(os.listdir(src))]
        for f in files:
            if not os.path.isfile(f):
                continue
            for pem in _pem_blocks(f):
                fp = _fingerprint(pem)
                if fp and fp not in COMPROMISED_ROOTS:
                    kept.setdefault(fp, pem)
    if not kept:
        return {}
    os.makedirs(work_dir, exist_ok=True)
    bundle = os.path.join(work_dir, "ca-bundle-filtered.pem")
    with open(bundle, "w", encoding="ascii") as fh:
        fh.write("\n".join(kept.values()) + "\n")
    empty_dir = os.path.join(work_dir, "ca-certs-empty")
    os.makedirs(empty_dir, exist_ok=True)
    return {"SSL_CERT_FILE": bundle, "SSL_CERT_DIR": empty_dir}


def _version_tuple(version: Optional[str]) -> Tuple[int, ...]:
    parts = []
    for p in (version or "").split(".")[:3]:
        digits = re.match(r"\d+", p)
        if not digits:
            break
        parts.append(int(digits.group()))
    return tuple(parts)


def mitigation_env(status: ToolchainStatus, work_dir: str) -> Dict[str, str]:
    """Environment overrides that stop *this* pip from trusting a bad root.

    Nothing can fix an old pip's own bundle; that still needs an upgrade.
    """
    env = filter_system_store(status, work_dir)
    # pip 24.2+ understands legacy-certs: use only its own bundle, not the OS
    # verifier. Only worth it when that bundle is clean.
    if (status.os_hits and not status.pip_hits and not status.legacy_certs
            and _version_tuple(status.pip_version) >= (24, 2)):
        current = os.environ.get("PIP_USE_DEPRECATED", "")
        env["PIP_USE_DEPRECATED"] = (current + " legacy-certs").strip()
    return env


def _names(hits: List[str]) -> str:
    return ", ".join(COMPROMISED_ROOTS.get(h, h[:16]) for h in hits)


def _python_too_old(version: Optional[str]) -> bool:
    v = _version_tuple(version)
    return len(v) >= 2 and v[:2] < (3, 10)


def describe(status: ToolchainStatus) -> List[str]:
    """Human-readable problem + fix lines for an affected toolchain."""
    lines: List[str] = []
    exe = status.executable
    if status.pip_hits:
        lines.append(
            f"pip {status.pip_version}'s own CA bundle trusts the compromised "
            f"eMudhra CAs via: {_names(status.pip_hits)}"
        )
        lines.append(f"  bundle: {status.pip_bundle}")
        if _python_too_old(status.python):
            lines.append(
                f"  Fix: pip {FIXED_PIP_VERSION} needs Python 3.10+; "
                f"upgrade Python ({status.python}) for this environment."
            )
        else:
            lines.append("  Fix (hash-pinned, safe even on a hostile network):")
            lines.append(f"    {exe} -m pip install \"{FIXED_PIP_REQUIREMENT}\"")
    if status.system_hits:
        lines.append(f"OpenSSL trust store still has: {_names(status.system_hits)}")
        lines.append(f"  stores: {', '.join(status.system_stores)}")
        lines.append(
            "  Fix: update ca-certificates (`sudo apt-get install --only-upgrade "
            "ca-certificates`, `brew upgrade ca-certificates`)."
        )
    if status.os_hits:
        used = " (not used: pip runs with legacy-certs)" if status.legacy_certs else ""
        lines.append(f"{status.os_store} still has: {_names(status.os_hits)}{used}")
        if not status.legacy_certs:
            lines.append(
                "  pip also asks the OS verifier. Install OS updates; until then use "
                "`PIP_USE_DEPRECATED=legacy-certs` (pipguard install does this for you)."
            )
    if lines:
        lines.append(f"  Details: {INCIDENT_URL}")
    return lines


# ── Online check against the incident's test hosts ───────────────────────────

def live_check(python: Optional[str] = None, env: Optional[Dict[str, str]] = None,
               timeout: int = 60) -> Dict[str, str]:
    """Ask pip itself to connect to hosts served by the compromised CAs.

    Returns host → "rejected" (safe), "ACCEPTED" (pip trusts the compromised
    CAs) or "unknown" (network error). This is ground truth for the exact pip
    and environment, including the OS verifier.
    """
    exe = python or sys.executable
    results: Dict[str, str] = {}
    run_env = dict(os.environ)
    run_env.update(env or {})
    with tempfile.TemporaryDirectory(prefix="pipguard-live-") as dest:
        for host in LIVE_TEST_HOSTS:
            cmd = [exe, "-m", "pip", "download", "--no-deps", "--no-cache-dir",
                   "--disable-pip-version-check", "--retries", "0", "--timeout", "15",
                   "--dest", dest, "--index-url", f"https://{host}/simple/",
                   "pipguard-live-check-nonexistent"]
            try:
                proc = subprocess.run(cmd, capture_output=True, text=True,
                                      timeout=timeout, env=run_env)
            except (OSError, subprocess.TimeoutExpired):
                results[host] = "unknown"
                continue
            out = (proc.stdout + proc.stderr).lower()
            if "certificate verify failed" in out or "problem confirming the ssl" in out:
                results[host] = "rejected"
            elif "from versions: none" in out:
                results[host] = "ACCEPTED"
            else:
                results[host] = "unknown"
    return results
