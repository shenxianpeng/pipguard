"""Risk aggregation, allowlist handling, and report formatting.

Architecture Amendment A3: CRITICAL findings are NEVER reduced by the allowlist.
Allowlist reduces HIGH → MEDIUM only.
"""

import sys
import unicodedata
from typing import Dict, Iterable, List, Optional

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

_REPORT_ORDER = (
    RiskLevel.CRITICAL,
    RiskLevel.HIGH,
    RiskLevel.MEDIUM,
    RiskLevel.LOW,
    RiskLevel.CLEAN,
)


def _color(text: str, level_name: str) -> str:
    if not _USE_COLOR:
        return text
    c = _COLORS.get(level_name, "")
    reset = _COLORS["RESET"]
    return f"{c}{text}{reset}"


def normalize_package_name(name: str) -> str:
    """Normalize package name: NFKC Unicode normalization, lowercase, hyphens (PEP 503).

    NFKC normalization collapses visually-identical Unicode characters (e.g.
    Cyrillic 'о' → Latin 'o') before the comparison, making homoglyph-based
    allowlist bypass attempts ineffective (TODO-2).
    """
    return unicodedata.normalize("NFKC", name).lower().replace("_", "-")


def check_package_name_for_homoglyph(package_name: str) -> Optional[Finding]:
    """Return a HIGH finding if the package name contains non-ASCII characters.

    PyPI technically disallows non-ASCII in normalised names, but a package
    published with a lookalike Unicode character (e.g. 'bоto3' with Cyrillic
    'о') can visually impersonate a trusted package.  Any non-ASCII character
    in the name is treated as a potential homoglyph / typosquatting attack
    (TODO-2).
    """
    for ch in package_name:
        if ord(ch) > 127:
            return Finding(
                level=RiskLevel.HIGH,
                file_path=package_name,
                line=0,
                description=(
                    f"package name contains non-ASCII character {ch!r} "
                    f"(U+{ord(ch):04X}) — possible homoglyph/typosquatting attack"
                ),
            )
    return None


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


def _finding_sort_key(finding: Finding) -> tuple:
    return (-finding.level.value, finding.file_path, finding.line, finding.description)


def _result_sort_key(result: PackageScanResult) -> tuple:
    return (-result.effective_level.value, normalize_package_name(result.package_name))


def _group_results(results: Iterable[PackageScanResult]) -> Dict[RiskLevel, List[PackageScanResult]]:
    grouped: Dict[RiskLevel, List[PackageScanResult]] = {level: [] for level in _REPORT_ORDER}
    for result in sorted(results, key=_result_sort_key):
        grouped[result.effective_level].append(result)
    return grouped


def _print_result_details(result: PackageScanResult) -> None:
    level = result.effective_level
    pkg = result.package_name

    if result.is_binary_only:
        print(f"  {_color('[UNKNOWN]', 'MEDIUM')} {pkg}")
        print("    Binary-only wheel — no Python source to scan.")
        print("    Verify independently or use --force to install.")
        return

    if not result.findings:
        print(f"  {_color('✓', 'CLEAN')} {pkg} — CLEAN")
        return

    print(f"  {_color(f'[{level}]', level.name)} {pkg}")
    if result.is_allowlisted and result.max_level == RiskLevel.HIGH:
        print("    (allowlisted — severity reduced from HIGH to MEDIUM)")

    for finding in sorted(result.findings, key=_finding_sort_key):
        lvl_tag = _color(f"[{finding.level}]", finding.level.name)
        print(f"    {lvl_tag} {finding.file_path}:{finding.line}")
        print(f"           {finding.description}")
        if finding.snippet:
            print(f"           -> {finding.snippet}")


def print_findings_report(results: List[PackageScanResult], verbose: bool = False) -> None:
    """Print a human-readable findings report to stdout."""
    grouped = _group_results(results)
    counts = {level: len(grouped[level]) for level in _REPORT_ORDER}

    print("Scan summary:")
    print(f"  Total packages: {len(results)}")
    print(
        "  " + "  ".join(
            f"{_color(level.name, level.name)}: {counts[level]}"
            for level in _REPORT_ORDER
        )
    )

    if counts[RiskLevel.CLEAN] == len(results) and not verbose:
        print("  All scanned packages are CLEAN.")
        return

    for level in _REPORT_ORDER:
        group = grouped[level]
        if not group:
            continue

        if level == RiskLevel.CLEAN and not verbose:
            continue

        print(f"\n{_color(level.name, level.name)}")

        if level == RiskLevel.LOW and not verbose:
            for result in group:
                count = len(result.findings)
                noun = "finding" if count == 1 else "findings"
                print(f"  {_color('[LOW]', 'LOW')} {result.package_name} — {count} {noun}")
            print("  Use --verbose to show LOW-level file details.")
            continue

        for result in group:
            _print_result_details(result)
