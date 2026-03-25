# pipguard

[![PyPI - Version](https://img.shields.io/pypi/v/pipguard)](https://pypi.org/project/pipguard/)
[![codecov](https://codecov.io/gh/shenxianpeng/pipguard/graph/badge.svg)](https://codecov.io/gh/shenxianpeng/pipguard)
[![Documentation](https://img.shields.io/badge/docs-mkdocs-blue)](https://shenxianpeng.github.io/pipguard/)

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

For the full reference — risk levels, exit codes, allowlist, and CI integration — see the **[documentation](https://shenxianpeng.github.io/pipguard/)**.

## License

MIT
