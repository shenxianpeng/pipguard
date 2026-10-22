"""Check that the pip pipguard drives does not trust a compromised CA.

pipguard downloads packages with ``python -m pip download``. If that pip trusts
a certificate authority whose key has leaked, anyone on the network path can
forge a certificate for pypi.org / files.pythonhosted.org and swap the bytes
pipguard is about to scan and install.

This happened in October 2026: the private keys behind eMudhra's
"emSign ECC Root CA - G3" intermediates were trivially weak, and certifi
2026.10.18/19 and pip 26.2.2 removed that root. Older pips always load their
vendored certifi bundle *in addition to* the system trust store, so updating the
OS store alone does not help. See
https://discuss.python.org/t/information-for-python-users-regarding-emudhra-emsign-ca-certificate-security-incident/109576

The check looks at the certificates pip will actually trust (its CA bundle,
which is the system bundle on distro-patched pips such as Debian's) rather than
just the pip version, so patched distro pips are not flagged and a future
incident only needs a new fingerprint in :data:`COMPROMISED_ROOTS`.
"""

from __future__ import annotations

import json
import subprocess
import sys
from dataclasses import dataclass, field
from typing import Dict, List, Optional

# SHA-256 fingerprint of the DER certificate → human-readable reason.
COMPROMISED_ROOTS: Dict[str, str] = {
    "86a1ecba089c4a8d3bbe2734c612ba341d813e043cf9e8a862cd5c57a36bbe6b": (
        "emSign ECC Root CA - G3 (eMudhra intermediate key compromise, Oct 2026)"
    ),
}

INCIDENT_URL = (
    "https://discuss.python.org/t/information-for-python-users-regarding-"
    "emudhra-emsign-ca-certificate-security-incident/109576"
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
# any interpreter. It imports pip the same way `python -m pip` does.
_PROBE = r'''
import base64, hashlib, json, os, re, ssl, sys
BAD = set(json.loads(sys.argv[1]))
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

res = {"python": sys.version.split()[0], "executable": sys.executable,
       "platform": sys.platform,
       "pip_version": None, "pip_bundle": None, "pip_hits": [],
       "system_stores": [], "system_hits": [], "error": None}
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

hits = set()
# cafile/capath already honour SSL_CERT_FILE / SSL_CERT_DIR, like OpenSSL.
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
if hasattr(ssl, "enum_certificates"):
    for store in ("ROOT", "CA"):
        try:
            for der, enc, _trust in ssl.enum_certificates(store):
                if enc == "x509_asn" and hashlib.sha256(der).hexdigest() in BAD:
                    hits.add(hashlib.sha256(der).hexdigest())
            res["system_stores"].append("windows:" + store)
        except Exception:
            pass
res["system_hits"] = sorted(hits)
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
    error: Optional[str] = None

    @property
    def compromised(self) -> bool:
        """True if any trust store this interpreter uses contains a bad CA."""
        return bool(self.pip_hits or self.system_hits)

    @property
    def blocking(self) -> bool:
        """True if pip downloads from this interpreter can be MITM'd.

        pip's own bundle is always loaded, so a hit there is decisive. On
        Linux pip (via truststore) also loads the OpenSSL system bundle we
        read, so a hit there counts too. On macOS/Windows pip asks the OS,
        which can distrust a root through mechanisms we cannot inspect, so a
        system hit there is only a warning.
        """
        if self.pip_hits:
            return True
        return bool(self.system_hits) and self.platform.startswith("linux")

    @property
    def checked(self) -> bool:
        """False when pip could not be inspected at all."""
        return self.pip_version is not None


def probe_toolchain(python: Optional[str] = None, timeout: int = 60) -> ToolchainStatus:
    """Inspect the pip and trust stores of ``python`` (default: this interpreter)."""
    exe = python or sys.executable
    try:
        proc = subprocess.run(
            [exe, "-c", _PROBE, json.dumps(sorted(COMPROMISED_ROOTS))],
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
        error=data.get("error"),
    )


def _python_too_old(version: Optional[str]) -> bool:
    try:
        major, minor = (int(x) for x in (version or "").split(".")[:2])
    except ValueError:
        return False
    return (major, minor) < (3, 10)


def describe(status: ToolchainStatus) -> List[str]:
    """Human-readable problem + fix lines for a compromised toolchain."""
    lines: List[str] = []
    exe = status.executable
    if status.pip_hits:
        names = ", ".join(COMPROMISED_ROOTS[h] for h in status.pip_hits)
        lines.append(
            f"pip {status.pip_version} trusts a compromised CA: {names}"
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
        names = ", ".join(COMPROMISED_ROOTS[h] for h in status.system_hits)
        lines.append(
            f"The system trust store still contains a compromised CA: {names}"
        )
        lines.append(f"  stores: {', '.join(status.system_stores)}")
        if status.platform.startswith("linux"):
            lines.append(
                "  pip also trusts this store (truststore), so update it: "
                "`sudo apt-get install --only-upgrade ca-certificates` "
                "(or your distro's equivalent)."
            )
        else:
            lines.append(
                "  Python's ssl module and OpenSSL-based tools use this store; "
                "update it (`brew upgrade ca-certificates`, OS updates)."
            )
    if lines:
        lines.append(f"  Details: {INCIDENT_URL}")
    return lines
