"""Query OSV.dev for known vulnerabilities in a package version.

osv.dev is an open-source vulnerability database that aggregates advisories
from multiple ecosystems (PyPI advisories, GitHub Security Advisories, etc.).
It is complementary to pipguard's AST-based static analysis: pipguard detects
suspicious behaviors in package code, while osv.dev matches known CVEs against
package versions.

Integration inspired by Issue #39.
"""

from __future__ import annotations

import json
import urllib.request
from dataclasses import dataclass, field
from typing import List, Optional


@dataclass
class OsvVulnerability:
    """A single known vulnerability from osv.dev."""

    vuln_id: str
    summary: str = ""
    severity: Optional[str] = None  # e.g. "CRITICAL", "HIGH", "MEDIUM", "LOW"
    aliases: List[str] = field(default_factory=list)  # e.g. CVE-2024-xxxx
    fixed_version: Optional[str] = None  # First patched version, if any

    @property
    def short_id(self) -> str:
        """Return the shortest recognizable ID (prefer CVE alias)."""
        for alias in self.aliases:
            if alias.startswith("CVE-"):
                return alias
        return self.vuln_id

    @property
    def one_line(self) -> str:
        """Human-readable one-line summary."""
        parts = [self.short_id]
        if self.severity:
            parts.append(f"[{self.severity}]")
        if self.summary:
            # Truncate long summaries
            s = self.summary.replace("\n", " ")
            if len(s) > 120:
                s = s[:117] + "..."
            parts.append(s)
        if self.fixed_version:
            parts.append(f"(fixed in {self.fixed_version})")
        return " ".join(parts)


# ═══════════════════════════════════════════════════════════════════════════
# OSV.dev v1 API client
# ═══════════════════════════════════════════════════════════════════════════

_OSV_QUERY_URL = "https://api.osv.dev/v1/query"
_OSV_TIMEOUT = 5  # seconds — fast failure to avoid slowing down scans


def query_osv(package_name: str, version: str, timeout: float = _OSV_TIMEOUT) -> List[OsvVulnerability]:
    """Query osv.dev for known vulnerabilities in a package version.

    Args:
        package_name: PyPI package name (e.g. "jinja2").
        version: Package version string (e.g. "2.4.1").
        timeout: Request timeout in seconds.

    Returns:
        A list of OsvVulnerability objects. Returns empty list on
        network error, timeout, invalid response, or no vulns found.
    """
    if not version:
        return []

    payload = json.dumps({
        "version": version,
        "package": {
            "name": package_name,
            "ecosystem": "PyPI",
        },
    }).encode("utf-8")

    try:
        req = urllib.request.Request(
            _OSV_QUERY_URL,
            data=payload,
            headers={
                "Content-Type": "application/json",
                "Accept": "application/json",
            },
            method="POST",
        )
        with urllib.request.urlopen(req, timeout=timeout) as resp:
            raw = resp.read().decode("utf-8", errors="replace")
    except Exception:
        return []  # Network error or timeout → graceful degradation

    try:
        data = json.loads(raw)
    except json.JSONDecodeError:
        return []

    return _parse_osv_response(data)


def _parse_osv_response(data: dict) -> List[OsvVulnerability]:
    """Parse osv.dev query response into OsvVulnerability objects."""
    vulns: List[OsvVulnerability] = []

    # osv.dev returns {"vulns": [...]} for matches, or {} for no match
    for entry in data.get("vulns", []) or []:
        vuln_id = entry.get("id", "")
        if not vuln_id:
            continue

        severity = None
        aliases: List[str] = []

        # Extract summary and severity from database_specific if present.
        db_specific = entry.get("database_specific") or {}
        summary = entry.get("summary", "") or ""
        if isinstance(db_specific, dict):
            if not summary and db_specific.get("summary"):
                summary = db_specific["summary"]
            if db_specific.get("severity"):
                severity = db_specific["severity"]

        # Collect aliases (CVE IDs, GHSA IDs, etc.)
        for alias in entry.get("aliases", []) or []:
            aliases.append(alias)

        # Try to find a fixed version from the affected ranges
        fixed_version = None
        for affected in entry.get("affected", []) or []:
            for rng in affected.get("ranges", []) or []:
                if rng.get("type") == "ECOSYSTEM":
                    for event in rng.get("events", []) or []:
                        if event.get("fixed"):
                            fixed_version = event["fixed"]
                            break
                if fixed_version:
                    break
            if fixed_version:
                break

        vulns.append(OsvVulnerability(
            vuln_id=vuln_id,
            summary=summary,
            severity=severity,
            aliases=aliases,
            fixed_version=fixed_version,
        ))

    return vulns
