"""Output formatters for pipguard scan results.

Supports:
- json: Machine-readable JSON output for CI/SIEM integration
- sarif: Static Analysis Results Interchange Format for GitHub Code Scanning
- text: Default human-readable output (handled by aggregator.print_findings_report)
"""

import json
from typing import Any, Dict, List

from .models import Finding, PackageScanResult, RiskLevel


def _finding_to_dict(finding: Finding) -> Dict[str, Any]:
    """Convert a Finding to a JSON-serializable dict."""
    d: Dict[str, Any] = {
        "level": finding.level.name,
        "file_path": finding.file_path,
        "line": finding.line,
        "description": finding.description,
    }
    if finding.snippet:
        d["snippet"] = finding.snippet
    return d


def _result_to_dict(result: PackageScanResult) -> Dict[str, Any]:
    """Convert a PackageScanResult to a JSON-serializable dict."""
    d: Dict[str, Any] = {
        "package_name": result.package_name,
        "version": result.version,
        "max_level": result.max_level.name,
        "effective_level": result.effective_level.name,
        "is_allowlisted": result.is_allowlisted,
        "is_binary_only": result.is_binary_only,
        "findings": [_finding_to_dict(f) for f in result.findings],
    }
    if result.cves:
        d["cves"] = [
            {
                "id": vuln.short_id,
                "summary": vuln.summary,
                "severity": vuln.severity,
                "aliases": vuln.aliases,
                "fixed_version": vuln.fixed_version,
            }
            for vuln in result.cves
        ]
    return d


def format_json(results: List[PackageScanResult]) -> str:
    """Format scan results as JSON."""
    output = {
        "schema_version": "1.0",
        "tool": "pipguard",
        "results": [_result_to_dict(r) for r in results],
        "summary": {
            "total_packages": len(results),
            "by_level": {
                level.name: sum(
                    1 for r in results if r.effective_level == level
                )
                for level in RiskLevel
            },
        },
    }
    return json.dumps(output, indent=2)


def _severity_to_sarif_level(level: RiskLevel) -> str:
    """Map pipguard RiskLevel to SARIF result level."""
    if level in (RiskLevel.CRITICAL, RiskLevel.HIGH):
        return "error"
    if level == RiskLevel.MEDIUM:
        return "warning"
    return "note"


def format_sarif(results: List[PackageScanResult]) -> str:
    """Format scan results as SARIF v2.1.0 for GitHub Code Scanning."""
    rules: List[Dict[str, Any]] = []
    rule_ids: Dict[str, int] = {}
    sarif_results: List[Dict[str, Any]] = []

    for result in results:
        for finding in result.findings:
            # Create a rule ID from the description pattern
            rule_id = _make_rule_id(finding.description)
            if rule_id not in rule_ids:
                rule_ids[rule_id] = len(rules)
                rules.append({
                    "id": rule_id,
                    "shortDescription": {"text": finding.description[:200]},
                    "defaultConfiguration": {
                        "level": _severity_to_sarif_level(finding.level),
                    },
                    "properties": {
                        "security-severity": _security_severity_score(finding.level),
                    },
                })

            sarif_result: Dict[str, Any] = {
                "ruleId": rule_id,
                "ruleIndex": rule_ids[rule_id],
                "level": _severity_to_sarif_level(finding.level),
                "message": {
                    "text": f"[{result.package_name}] {finding.description}",
                },
                "locations": [
                    {
                        "physicalLocation": {
                            "artifactLocation": {
                                "uri": finding.file_path,
                            },
                            "region": {
                                "startLine": max(finding.line, 1),
                            },
                        },
                    }
                ],
            }
            sarif_results.append(sarif_result)

        # Also emit CVE findings
        for vuln in result.cves:
            rule_id = f"osv/{vuln.short_id}"
            if rule_id not in rule_ids:
                rule_ids[rule_id] = len(rules)
                rules.append({
                    "id": rule_id,
                    "shortDescription": {"text": vuln.summary[:200] if vuln.summary else vuln.short_id},
                    "defaultConfiguration": {"level": "error"},
                    "helpUri": f"https://osv.dev/vulnerability/{vuln.vuln_id}",
                    "properties": {
                        "security-severity": "9.0",
                    },
                })
            sarif_results.append({
                "ruleId": rule_id,
                "ruleIndex": rule_ids[rule_id],
                "level": "error",
                "message": {
                    "text": (
                        f"[{result.package_name}=={result.version}] "
                        f"Known vulnerability: {vuln.one_line}"
                    ),
                },
                "locations": [
                    {
                        "physicalLocation": {
                            "artifactLocation": {"uri": "requirements.txt"},
                            "region": {"startLine": 1},
                        },
                    }
                ],
            })

    sarif = {
        "$schema": "https://raw.githubusercontent.com/oasis-tcs/sarif-spec/main/sarif-2.1/schema/sarif-schema-2.1.0.json",
        "version": "2.1.0",
        "runs": [
            {
                "tool": {
                    "driver": {
                        "name": "pipguard",
                        "informationUri": "https://github.com/shenxianpeng/pipguard",
                        "rules": rules,
                    },
                },
                "results": sarif_results,
            }
        ],
    }
    return json.dumps(sarif, indent=2)


def _make_rule_id(description: str) -> str:
    """Generate a stable rule ID from a finding description."""
    # Extract the core pattern from the description
    desc_lower = description.lower()
    if "network" in desc_lower or "socket" in desc_lower or "urlopen" in desc_lower:
        return "pipguard/network-access"
    if "credential" in desc_lower or ".ssh" in desc_lower or ".aws" in desc_lower:
        return "pipguard/credential-access"
    if "exec" in desc_lower or "eval" in desc_lower:
        return "pipguard/code-execution"
    if "subprocess" in desc_lower or "os.system" in desc_lower or "shell" in desc_lower:
        return "pipguard/shell-execution"
    if ".pth" in desc_lower:
        return "pipguard/pth-autorun"
    if "binary" in desc_lower:
        return "pipguard/binary-extension"
    if "homoglyph" in desc_lower or "non-ascii" in desc_lower:
        return "pipguard/homoglyph-attack"
    if "intel" in desc_lower:
        return "pipguard/intel-blocked"
    if "import" in desc_lower:
        return "pipguard/dynamic-import"
    if "env" in desc_lower:
        return "pipguard/sensitive-env-access"
    return "pipguard/suspicious-behavior"


def _security_severity_score(level: RiskLevel) -> str:
    """Map RiskLevel to a CVSS-like security-severity score string."""
    scores = {
        RiskLevel.CRITICAL: "9.5",
        RiskLevel.HIGH: "8.0",
        RiskLevel.MEDIUM: "5.5",
        RiskLevel.LOW: "3.0",
        RiskLevel.CLEAN: "0.0",
    }
    return scores.get(level, "5.0")
