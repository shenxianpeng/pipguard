# pipguard

**Python supply chain security tool. Scan packages before installing them.**

```bash
pip install pipguard
pipguard install litellm==1.82.8   # Blocks the March 2026 attack. Exits 1.
```

Zero configuration. Zero external dependencies. Pure stdlib.

---

## The Problem

The March 2026 litellm attack (97M downloads/month) embedded Python code in a `.pth`
file — executed automatically at interpreter startup, exfiltrating SSH keys, AWS credentials,
and Kubernetes configs from a single `pip install`.

Classical tools (pip-audit, GuardDog) are blind to zero-day attacks. They check known
signatures. pipguard asks a different question:

> Should **any** `pip install` be allowed to read `~/.ssh/id_rsa`?

The answer is **no**. And that question doesn't require a database.

## Installation

```bash
pip install pipguard
```

## Usage

```bash
# Install a single package
pipguard install requests

# Install from requirements.txt
pipguard install -r requirements.txt

# CI mode: never prompts, exits 1 on CRITICAL/HIGH
pipguard install --yes -r requirements.txt

# Allow a known-legitimate package that accesses credentials
pipguard install --allow paramiko paramiko

# Override for known false-positives (use with care)
pipguard install --force my-trusted-internal-pkg
```

## How It Works

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

## Risk Levels

| Level    | Triggers |
|----------|----------|
| CRITICAL | `.pth` executable code; `eval(base64.b64decode(...))`; network in `setup.py` |
| HIGH     | Reads `~/.ssh`, `~/.aws`, `~/.kube`, `~/.gnupg` in install hooks; `shell=True` subprocess |
| MEDIUM   | Network calls in runtime code; sensitive env var access (`*TOKEN*`, `*KEY*`, etc.) |
| LOW      | Dynamic `importlib`/`__import__` |
| CLEAN    | None of the above |

## Exit Codes

| Code | Meaning |
|------|---------|
| 0    | Clean install succeeded |
| 1    | Blocked — CRITICAL or HIGH risk detected |
| 2    | Scan error (download failed, unsupported format) |

## GitHub Action

```yaml
- name: Secure pip install
  uses: pipguard/action@v1
  with:
    requirements: requirements.txt
```

## Seed Allowlist

These packages legitimately access credential stores and are pre-allowlisted
(HIGH reduced to MEDIUM — CRITICAL is **never** reduced):

`keyring`, `keyrings.alt`, `boto3`, `botocore`, `awscli`, `paramiko`,
`google-auth`, `google-cloud-storage`, `google-cloud-bigquery`,
`google-cloud-core`, `azure-identity`

Add more per-invocation: `pipguard install --allow my-package ...`

## Limitations (Phase 1)

- Static AST scanning can be bypassed by multi-layer obfuscation
- C extensions (`.so`/`.pyd`) are opaque to AST scanning (flagged as UNKNOWN)
- Python/pip only — no npm, cargo, go modules
- Phase 2 (in design): seccomp/eBPF sandbox for zero-day capability interception

## License

MIT
