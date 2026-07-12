#!/usr/bin/env python3
"""pipguard detection benchmark — measures TPR / FPR against a labeled corpus.

The corpus (``benchmark/corpus.json`` + ``benchmark/corpus/``) contains three
kinds of labeled samples:

- ``malicious`` — real attack patterns that MUST be blocked
- ``bypass``    — evasion variants of the same, that MUST also be blocked
- ``benign``    — legitimate code that MUST NOT be blocked

"Blocked" mirrors the install gate: an effective finding of HIGH or CRITICAL.

Metrics:
- **TPR** (recall) = detected / total over malicious + bypass samples
- **FPR**          = falsely-blocked / total over benign samples

Run directly (``python benchmark/run_benchmark.py`` or ``make benchmark``) for a
human-readable report, or import :func:`evaluate` for programmatic use (the
enforcing test in ``tests/test_benchmark.py`` does this).
"""

from __future__ import annotations

import json
import os
import sys
from dataclasses import dataclass
from typing import Dict, List

sys.path.insert(0, os.path.join(os.path.dirname(__file__), ".."))

from pipguard.models import RiskLevel
from pipguard.scanner import scan_pth_file, scan_python_file

BENCHMARK_DIR = os.path.dirname(os.path.abspath(__file__))
CORPUS_MANIFEST = os.path.join(BENCHMARK_DIR, "corpus.json")
CORPUS_ROOT = os.path.join(BENCHMARK_DIR, "corpus")

# The install gate blocks HIGH and CRITICAL.
_BLOCK_LEVELS = {RiskLevel.HIGH, RiskLevel.CRITICAL}


@dataclass
class SampleResult:
    file: str
    category: str          # malicious | bypass | benign
    expect: str            # block | allow
    max_level: RiskLevel
    blocked: bool

    @property
    def correct(self) -> bool:
        return self.blocked == (self.expect == "block")


def _scan_sample(path: str, scope: str) -> RiskLevel:
    """Scan one sample file and return the max finding level."""
    if path.endswith(".pth"):
        findings = scan_pth_file(path)
    else:
        findings = scan_python_file(path, is_hook=(scope == "hook"))
    if not findings:
        return RiskLevel.CLEAN
    return max((f.level for f in findings), key=lambda level: level.value)


def evaluate(manifest_path: str = CORPUS_MANIFEST) -> Dict:
    """Run the benchmark and return a metrics dict."""
    with open(manifest_path, encoding="utf-8") as f:
        manifest = json.load(f)

    results: List[SampleResult] = []
    for entry in manifest:
        category = entry["file"].split("/", 1)[0]
        path = os.path.join(CORPUS_ROOT, entry["file"])
        max_level = _scan_sample(path, entry["scope"])
        results.append(SampleResult(
            file=entry["file"],
            category=category,
            expect=entry["expect"],
            max_level=max_level,
            blocked=max_level in _BLOCK_LEVELS,
        ))

    attack = [r for r in results if r.expect == "block"]
    benign = [r for r in results if r.expect == "allow"]

    detected = sum(1 for r in attack if r.blocked)
    false_pos = sum(1 for r in benign if r.blocked)

    tpr = detected / len(attack) if attack else 0.0
    fpr = false_pos / len(benign) if benign else 0.0

    return {
        "tpr": tpr,
        "fpr": fpr,
        "attack_total": len(attack),
        "attack_detected": detected,
        "benign_total": len(benign),
        "benign_false_positive": false_pos,
        "results": results,
    }


def _print_report(metrics: Dict) -> None:
    results: List[SampleResult] = metrics["results"]
    print("pipguard detection benchmark")
    print("=" * 60)
    for r in sorted(results, key=lambda r: (r.category, r.file)):
        status = "ok " if r.correct else "MISS"
        print(f"  [{status}] {r.file:44} {r.max_level.name:8} "
              f"(expect {r.expect})")
    print("-" * 60)
    print(f"  TPR (malicious+bypass detected): "
          f"{metrics['attack_detected']}/{metrics['attack_total']} "
          f"= {metrics['tpr']:.1%}")
    print(f"  FPR (benign falsely blocked):    "
          f"{metrics['benign_false_positive']}/{metrics['benign_total']} "
          f"= {metrics['fpr']:.1%}")


def main() -> int:
    metrics = evaluate()
    _print_report(metrics)
    misses = [r for r in metrics["results"] if not r.correct]
    return 1 if misses else 0


if __name__ == "__main__":
    sys.exit(main())
