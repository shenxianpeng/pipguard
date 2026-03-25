"""Risk aggregation, allowlist handling, and report formatting.

Architecture Amendment A3: CRITICAL findings are NEVER reduced by the allowlist.
Allowlist reduces HIGH → MEDIUM only.
"""

import sys
from typing import List, Optional

from .models import Finding, PackageScanResult, RiskLevel

# Seed allowlist v0.1 — packages known to legitimately access credential paths.
# Exact name matching only (no glob/prefix). Homoglyph normalization applied.
# Allowlist reduces HIGH → MEDIUM. CRITICAL is never reduced.
SEED_ALLOWLIST: frozenset = frozenset({
    "keyring",
    "keyrings.alt",
    "boto3",
    "botocore",
    "awscli",
    "paramiko",
    "google-auth",
    "google-cloud-storage",
    "google-cloud-bigquery",
    "google-cloud-core",
    "azure-identity",
})

# ANSI color codes (disabled in CI via NO_COLOR env var)
_USE_COLOR = sys.stdout.isatty() and not __import__("os").environ.get("NO_COLOR")

_COLORS = {
    "CRITICAL": "\033[91m",  # bright red
    "HIGH":     "\033[31m",  # red
    "MEDIUM":   "\033[33m",  # yellow
    "LOW":      "\033[34m",  # blue
    "CLEAN":    "\033[32m",  # green
    "RESET":    "\033[0m",
}


def _color(text: str, level_name: str) -> str:
    if not _USE_COLOR:
        return text
    c = _COLORS.get(level_name, "")
    reset = _COLORS["RESET"]
    return f"{c}{text}{reset}"


def normalize_package_name(name: str) -> str:
    """Normalize package name: lowercase, hyphens (PEP 503)."""
    return name.lower().replace("_", "-")


def is_allowlisted(package_name: str, extra_allow: Optional[List[str]] = None) -> bool:
    """Check if a package is in the compiled or per-invocation allowlist."""
    normalized = normalize_package_name(package_name)
    all_allowed = SEED_ALLOWLIST | {
        normalize_package_name(p) for p in (extra_allow or [])
    }
    return normalized in all_allowed


def aggregate_findings(
    package_name: str,
    findings: List[Finding],
    extra_allow: Optional[List[str]] = None,
    is_binary_only: bool = False,
    version: str = "",
) -> PackageScanResult:
    """Aggregate findings for a package, applying allowlist rules."""
    allowlisted = is_allowlisted(package_name, extra_allow)
    return PackageScanResult(
        package_name=package_name,
        version=version,
        findings=findings,
        is_allowlisted=allowlisted,
        is_binary_only=is_binary_only,
    )


def print_findings_report(results: List[PackageScanResult]) -> None:
    """Print a human-readable findings report to stdout."""
    any_findings = any(r.findings or r.is_binary_only for r in results)

    if not any_findings:
        print(_color("✓ All packages scanned CLEAN.", "CLEAN"))
        return

    for result in results:
        level = result.effective_level
        pkg = result.package_name

        if result.is_binary_only:
            print(f"\n{_color('[UNKNOWN]', 'MEDIUM')} {pkg}")
            print("  Binary-only wheel — no Python source to scan.")
            print("  Verify independently or use --force to install.")
            continue

        if not result.findings:
            print(f"  {_color('✓', 'CLEAN')} {pkg} — CLEAN")
            continue

        print(f"\n{_color(f'[{level}]', level.name)} {pkg}")
        if result.is_allowlisted and result.max_level == RiskLevel.HIGH:
            print("  (allowlisted — severity reduced from HIGH to MEDIUM)")

        for finding in sorted(result.findings, key=lambda f: f.level.value, reverse=True):
            lvl_tag = _color(f"[{finding.level}]", finding.level.name)
            print(f"  {lvl_tag} {finding.file_path}:{finding.line}")
            print(f"         {finding.description}")
            if finding.snippet:
                print(f"         → {finding.snippet}")
