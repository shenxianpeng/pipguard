> 本页面提供中文入口，内容将持续完善。

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
| Shell/subprocess execution in install hooks (`os.system`, `os.popen`, shell execution via `subprocess`) | Install-time command execution is a high-confidence attacker primitive and is blocked by default. |

!!! danger "CRITICAL is never reduced"
    The `--allow` flag and the seed allowlist do **not** reduce CRITICAL findings.
    Only `--force` bypasses CRITICAL — use with extreme caution.

## HIGH

**Action: Block. Exit 1. No confirmation prompt.**

| Trigger | Scope | Why |
|---------|-------|-----|
| Non-ASCII character in package name | Name check (pre-scan) | Possible homoglyph / typosquatting attack (e.g. `bоto3` with Cyrillic `о` instead of Latin `o`). |
| Reads credential paths (`~/.ssh`, `~/.aws`, `~/.kube`, `~/.gnupg`) | Install hooks only | A package reading your SSH keys during `pip install` is an attack, not a feature. |
| Direct subprocess execution (non-shell) | Install hooks only | Elevated risk in install-time context; surfaced as HIGH for manual review. |
| Binary IOC credential markers (`/.ssh/id_rsa`, `/.aws/credentials`) | Binary extension scan | Heuristic binary content includes hard-coded credential path indicators. |

!!! warning "HIGH in runtime code"
    If the same patterns appear in *runtime* code (not install hooks), the finding is
    downgraded to MEDIUM. `boto3` legitimately reads `~/.aws` at runtime — that's fine.
    It reading `~/.aws` in `setup.py` is not.

## MEDIUM

**Action: Warn and prompt for confirmation. (`--yes` skips prompt and proceeds.)**

| Trigger | Notes |
|---------|-------|
| Binary-only wheel (no Python source) | Wheel contains only `.so` / `.pyd` / `.dylib` files — AST scan cannot verify contents. Confirmation gate fires; use `--yes` to proceed. |
| Network calls in runtime `.py` files | Common in legitimate packages; shown for transparency |
| Sensitive env var access (`*TOKEN*`, `*KEY*`, `*SECRET*`, `*PASSWORD*`, `*CREDENTIAL*`) | Flagged in runtime code |
| Large source file over 1MB | Scanner continues, but emits confidence-reduction warning for manual review |
| Binary IOC string indicators (`https://`, `/bin/sh`, `socket`) | Heuristic binary scan detected suspicious runtime/exfil primitives |

## LOW

**Action: Warn (shown in summary). Confirmation prompt fires (skippable with `--yes`).**

| Trigger | Notes |
|---------|-------|
| Compiled binary extension in mixed wheel | `.so` / `.pyd` / `.dylib` file present alongside Python source — AST scanner is blind to any payload in compiled code |
| `importlib.import_module(variable)` | Dynamic imports can load arbitrary code |
| `__import__(variable)` | Same concern as above |

## CLEAN

**Action: Install silently.**

No patterns matching CRITICAL, HIGH, MEDIUM, or LOW were found.
The package installs without any output.
