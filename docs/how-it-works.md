# How It Works

pipguard's design has one rule: **code must never execute during scanning**.

## Architecture

```
pipguard install X
       │
       ▼
pip download --prefer-binary X    ← downloads wheel/sdist, no code execution
       │
       ▼
Detect sdist fallback             ← exit 2 if sdist detected (unless --allow-sdist)
       │
       ▼
Extract archive (zipfile/tarfile) ← never executes code
       │
       ▼
AST scan all .py files            ← parallel, ThreadPoolExecutor
  setup.py, pyproject.toml, *.pth ← CRITICAL/HIGH scope
  all other .py                   ← MEDIUM/LOW scope
       │
       ▼
Risk scoring:
  CRITICAL → block (exit 1)
  HIGH     → block (exit 1)
  MEDIUM   → warn + confirm
  LOW      → warn + confirm
  CLEAN    → install silently
       │
       ▼
pip install --no-index            ← installs FROM SCANNED FILES (TOCTOU-safe)
    --find-links /tmp/pipguard-XX
```

## Why Pre-Install?

Classical security tools (pip-audit, Safety, GuardDog) work post-hoc — they check installed packages against known-bad signature databases. This means:

1. **Zero-day blind spot** — a new attack not yet in the database walks straight through
2. **Race condition** — the malicious code has already run by the time the tool checks

pipguard reverses the order. It asks: *does this code do something that **any** pip install should be allowed to do?*

Regardless of whether the package is on any watchlist, the answer to "reads `~/.ssh/id_rsa` and sends it over a network" is always **no**.

## TOCTOU Safety

A subtle attack vector: scan a clean file, then swap it for a malicious one before install.

pipguard counters this by:

1. Downloading the archive to a temp directory
2. Scanning the files **in place** in that temp directory
3. Running `pip install --no-index --find-links /tmp/pipguard-XX` — installing the exact files that were scanned

The archive is never re-downloaded or re-extracted after scanning.

## AST Scanning

pipguard uses Python's built-in `ast` module — no third-party dependencies — to parse `.py` files into abstract syntax trees and walk the nodes looking for dangerous patterns.

### What gets flagged

=== "CRITICAL"

    | Pattern | Example |
    |---------|---------|
    | `.pth` file with executable Python | `import os; os.system(...)` in `.pth` |
    | Obfuscated eval | `eval(base64.b64decode(...))` |
    | Network in `setup.py` / install hooks | `urllib.request.urlopen(...)` in `setup.py` |

=== "HIGH"

    | Pattern | Example |
    |---------|---------|
    | Credential path read in install hooks | `open('~/.ssh/id_rsa')` in `setup.py` |
    | Shell subprocess in install hooks | `subprocess.run(..., shell=True)` |
    | `os.system()` / `os.popen()` in install hooks | `os.system('curl ...')` |

=== "MEDIUM"

    | Pattern | Example |
    |---------|---------|
    | Network in runtime code | `urllib.request.urlopen(...)` in `utils.py` |
    | Sensitive env var access | `os.environ.get('AWS_SECRET_ACCESS_KEY')` |

=== "LOW"

    | Pattern | Example |
    |---------|---------|
    | Dynamic imports | `importlib.import_module(name)` |
    | `__import__()` | `__import__(variable)` |

## Seed Allowlist

Some packages legitimately access credentials as part of their core purpose.
pipguard ships with a seed allowlist that reduces their finding from HIGH to MEDIUM
(CRITICAL is **never** reduced):

`keyring`, `keyrings.alt`, `boto3`, `botocore`, `awscli`, `paramiko`,
`google-auth`, `google-cloud-storage`, `google-cloud-bigquery`,
`google-cloud-core`, `azure-identity`

[Full allowlist reference →](allowlist.md)

## Limitations

!!! note "Phase 1 scope"
    These are known limitations of the current static-analysis approach.

- **Obfuscation** — multi-layer obfuscation (e.g. `exec(compile(...))` wrapped multiple times) may evade detection
- **C extensions** — `.so` / `.pyd` binaries are opaque to AST scanning (flagged as UNKNOWN)
- **Python/pip only** — no npm, cargo, or go module support
- **Phase 2 (in design)** — seccomp/eBPF sandbox for capability-level interception at runtime
