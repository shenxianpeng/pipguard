---
template: landing.html
title: pipguard
hero:
  eyebrow: supply chain security · python · zero config
  title: "Block the attack<br>*before it lands.*"
  text: >-
    **pipguard** scans every package via AST analysis *before* code runs.
    No database. No network calls. No configuration. Just a guard at the door.
  actions:
    - {text: pip install pipguard, link: installation.md, icon: download, primary: true}
    - {text: Read the docs, link: usage.md, icon: book-open}
  code:
    title: bash — pipguard
    lang: text
    content: |
      $ pipguard install litellm==1.82.8

      → Downloading wheel (no code executed)
      → Extracting archive
      → AST scanning 47 files

        setup.py          ............... CLEAN
        utils/loader.py   ............... CLEAN
        .pth files        ............... CRITICAL

        ─────────────────────────────────────

        ✗ BLOCKED: litellm==1.82.8
        .pth autorun · reads ~/.ssh/id_rsa
        exfiltrates to 44.202.x.x:4444

        Severity: CRITICAL · Exit code: 1
sections:
  - type: features
    columns: 4
    items:
      - {icon: sliders-horizontal, title: Zero config}
      - {icon: package, title: Pure stdlib}
      - {icon: shield-x, title: Blocks before install}
      - {icon: workflow, title: CI-ready}
  - type: content
---

## The Problem

The March 2026 litellm attack (97M downloads/month) embedded Python code in a `.pth`
file — executed automatically at interpreter startup, exfiltrating SSH keys, AWS credentials,
and Kubernetes configs from a single `pip install`.

Classical tools (pip-audit, GuardDog) are blind to zero-day attacks. They check known
signatures. pipguard asks a different question:

!!! danger "The question classical tools never ask"
    Should **any** `pip install` be allowed to read `~/.ssh/id_rsa`?

    The answer is **no**. And that question doesn't require a database.

## How It Works

1. pip download

    Downloads wheel or sdist. No code runs. Ever.

2. Sdist check

    Exit 2 if sdist detected — build scripts are unsafe.

3. Extract

    zipfile/tarfile only. No subprocess. No exec.

4. AST scan

    Parallel scan of all .py files. CRITICAL scope on .pth, setup.py.

5. Risk score

    CRITICAL/HIGH → exit 1. CLEAN → install silently.
{.steps}

## Risk Levels at a Glance

| Level | What triggers it | Action |
|-------|-----------------|--------|
| **CRITICAL**{.badge .caution} | `.pth` executable code; `eval(base64.b64decode(...))` | Block (exit 1) |
| **HIGH**{.badge .warning} | Non-ASCII package name (homoglyph); reads `~/.ssh`, `~/.aws` in install hooks; `shell=True`; `os.system()` | Block (exit 1) |
| **MEDIUM**{.badge .note} | Binary-only wheel; network in runtime; sensitive env vars | Warn + confirm |
| LOW | Compiled binary extension in mixed wheel; dynamic imports | Warn + confirm |
| CLEAN | None of the above | Install silently |

[Full risk level reference →](risk-levels.md)
