# pipguard detection benchmark

A hermetic, checked-in benchmark that measures pipguard's **detection rate**
(TPR) and **false-positive rate** (FPR) against a labeled corpus. It runs
offline — no packages are downloaded — so it is reproducible and CI-safe.

## Corpus

`corpus.json` is the manifest; sample files live under `corpus/`:

| Category    | Expectation      | What it contains |
|-------------|------------------|------------------|
| `malicious` | must be **blocked** | real attack patterns: `.pth` autorun, `exec(b64decode(...))`, credential reads, shell/network in install hooks, unsafe deserialization |
| `bypass`    | must be **blocked** | evasion variants: aliased/assigned network calls, `getattr`/`__import__` reflection, `os.path.join` credential construction, `bash -c` subprocess |
| `benign`    | must **not** be blocked | legitimate code: ordinary path joins, metadata-only `setup.py`, plugin `importlib`, runtime network/env/subprocess |

"Blocked" mirrors the install gate: an effective finding of **HIGH** or
**CRITICAL**. Benign samples may legitimately produce LOW/MEDIUM findings.

## Metrics

- **TPR** (recall) = detected / total over `malicious` + `bypass`
- **FPR**          = falsely-blocked / total over `benign`

## Running

```bash
make benchmark          # human-readable report
python benchmark/run_benchmark.py
```

The baseline is enforced in CI by `tests/test_benchmark.py`: **TPR must be 100%
and FPR must be 0%** on the current corpus. Weakening a rule so it misses an
attack, or adding an over-broad rule that trips a benign pattern, fails the
suite.

## Current baseline

See `baseline.json` — TPR 100% (18/18), FPR 0% (0/8).

> This benchmark already paid for itself: it surfaced a false negative where
> `import urllib.request; urllib.request.urlopen(...)` in an install hook went
> undetected (a dotted-import alias-resolution bug), now fixed and covered here.

## Extending

Add a sample file under `corpus/<category>/` and a matching entry in
`corpus.json` (`file`, `scope` = `hook`|`runtime`, `expect` = `block`|`allow`,
`desc`). Real-package benign samples can be added to harden the FPR measurement
over time.
