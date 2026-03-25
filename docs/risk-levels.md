# Risk Levels

pipguard assigns every scanned package one of five risk levels based on patterns
found during static AST analysis.

## CRITICAL

**Action: Block immediately. Exit 1. No confirmation prompt.**

| Trigger | Why it's CRITICAL |
|---------|------------------|
| `.pth` file containing executable Python code | `.pth` files are executed automatically at Python interpreter startup — before any user code runs. Any executable content is unambiguously malicious. |
| `eval(base64.b64decode(...))` in any file | Classic obfuscated payload pattern. Legitimate packages never need this. |
| Network calls (`urllib`, `httpx`, `requests`, `socket`) in `setup.py` or install hooks | Build-time network calls have no legitimate use case. The March 2026 litellm attack used this to exfiltrate data. |

!!! danger "CRITICAL is never reduced"
    The `--allow` flag and the seed allowlist do **not** reduce CRITICAL findings.
    Only `--force` bypasses CRITICAL — use with extreme caution.

## HIGH

**Action: Block. Exit 1. No confirmation prompt.**

| Trigger | Scope | Why |
|---------|-------|-----|
| Reads credential paths (`~/.ssh`, `~/.aws`, `~/.kube`, `~/.gnupg`) | Install hooks only | A package reading your SSH keys during `pip install` is an attack, not a feature. |
| `subprocess.run(..., shell=True)` | Install hooks only | Shell injection risk; no legitimate build script needs `shell=True`. |
| `os.system()` / `os.popen()` | Install hooks only | Arbitrary shell execution at install time. |

!!! warning "HIGH in runtime code"
    If the same patterns appear in *runtime* code (not install hooks), the finding is
    downgraded to MEDIUM. `boto3` legitimately reads `~/.aws` at runtime — that's fine.
    It reading `~/.aws` in `setup.py` is not.

## MEDIUM

**Action: Warn and prompt for confirmation. (`--yes` skips prompt and proceeds.)**

| Trigger | Notes |
|---------|-------|
| Network calls in runtime `.py` files | Common in legitimate packages; shown for transparency |
| Sensitive env var access (`*TOKEN*`, `*KEY*`, `*SECRET*`, `*PASSWORD*`, `*CREDENTIAL*`) | Flagged in runtime code |

## LOW

**Action: Warn (shown in summary). Does not block.**

| Trigger | Notes |
|---------|-------|
| `importlib.import_module(variable)` | Dynamic imports can load arbitrary code |
| `__import__(variable)` | Same concern as above |

## CLEAN

**Action: Install silently.**

No patterns matching CRITICAL, HIGH, MEDIUM, or LOW were found.
The package installs without any output.
