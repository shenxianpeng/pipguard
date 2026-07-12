"""Enforce the detection benchmark baseline (Issue #54).

Runs the labeled corpus in ``benchmark/`` and fails CI if detection regresses:
every malicious/bypass sample must be blocked (TPR = 100%) and no benign sample
may be blocked (FPR = 0%). Tightening a rule that misses an attack, or adding an
over-broad rule that trips a benign pattern, breaks this test.
"""

import os
import sys

sys.path.insert(0, os.path.join(os.path.dirname(__file__), "..", "benchmark"))

from run_benchmark import evaluate  # noqa: E402


def test_benchmark_no_false_negatives():
    """All malicious + bypass samples are blocked (TPR = 100%)."""
    metrics = evaluate()
    misses = [
        r for r in metrics["results"]
        if r.expect == "block" and not r.blocked
    ]
    assert not misses, (
        "undetected attack samples: "
        + ", ".join(r.file for r in misses)
    )
    assert metrics["tpr"] == 1.0


def test_benchmark_no_false_positives():
    """No benign sample is blocked (FPR = 0%)."""
    metrics = evaluate()
    false_positives = [
        r for r in metrics["results"]
        if r.expect == "allow" and r.blocked
    ]
    assert not false_positives, (
        "benign samples wrongly blocked: "
        + ", ".join(f"{r.file} ({r.max_level.name})" for r in false_positives)
    )
    assert metrics["fpr"] == 0.0
