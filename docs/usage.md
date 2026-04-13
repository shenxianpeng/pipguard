# Usage

![pipguard demo](assets/demo.gif)

## Basic Usage

### Install a single package

```bash
pipguard install requests
```

pipguard will download, scan, and — if clean — install the package. No output means no findings.

### Install from requirements.txt

```bash
pipguard install -r requirements.txt
```

Scans all packages in the file. Blocks on first CRITICAL or HIGH finding.

## CI Mode

In CI, you never want interactive prompts. Use `--yes` to suppress all confirmation prompts
and have pipguard exit 1 automatically on CRITICAL or HIGH findings:

```bash
pipguard install --yes -r requirements.txt
```

<div class="pg-terminal">
  <div class="pg-terminal__bar">
    <div class="pg-terminal__dot"></div>
    <div class="pg-terminal__dot"></div>
    <div class="pg-terminal__dot"></div>
    <span class="pg-terminal__title">GitHub Actions</span>
  </div>
  <div class="pg-terminal__body">
    <div><span class="t-dollar">$</span><span class="t-cmd">pipguard install --yes -r requirements.txt</span></div>
    <div>&nbsp;</div>
    <div><span class="t-ok">✓ requests==2.31.0</span></div>
    <div><span class="t-ok">✓ numpy==1.26.3</span></div>
    <div><span class="t-block">✗ litellm==1.82.8  CRITICAL — .pth autorun, reads ~/.ssh/id_rsa</span></div>
    <div>&nbsp;</div>
    <div><span class="t-block">Process exited with code 1</span></div>
  </div>
</div>

## Allowing Known-Legitimate Packages

Some packages legitimately access credential stores (e.g. `paramiko` reads `~/.ssh`).
Use `--allow` to reduce their finding from HIGH to MEDIUM:

```bash
pipguard install --allow paramiko paramiko
```

!!! warning "CRITICAL findings are never reduced"
    `--allow` only reduces HIGH → MEDIUM. CRITICAL findings always block, regardless of flags.

## Forcing a Package (Escape Hatch)

For known false-positives on fully-trusted internal packages:

```bash
pipguard install --force my-trusted-internal-pkg
```

!!! danger "Use with care"
    `--force` bypasses all checks and logs a warning. Never use in CI without code review.

## Allowing sdist Packages

By default pipguard exits with code 2 if a package falls back to sdist (source distribution),
because sdists execute build scripts. To opt in:

```bash
pipguard install --allow-sdist some-package
```

!!! danger "sdist installs execute arbitrary code"
    `--allow-sdist` bypasses a hard safety boundary. Even though pipguard runs AST scanning on
    `setup.py`, `pip install` will still **execute** setup.py and any build-backend code at
    install time. pipguard's AST scan does **NOT** prevent this.
    Never use `--allow-sdist` in automated pipelines without explicit review.

## All Flags

| Flag | Description |
|------|-------------|
| `-r FILE` | Install from requirements file |
| `--yes` / `-y` | CI mode — no prompts, exit 1 on CRITICAL/HIGH |
| `--allow PKG` | Add package to per-invocation allowlist (HIGH→MEDIUM) |
| `--force PKG` | Bypass all checks for a specific package |
| `--allow-sdist` | Allow sdist fallback (DANGER: executes arbitrary code — AST scan does NOT prevent this) |
| `--require-hashes` | Require hash-locked requirements entries (`--hash=...` or URL hash fragment) |
| `--policy FILE` | Load policy file (default: `./pipguard.toml` if present) |
| `--intel-feed FILE_OR_URL` | Threat-intel JSON feed containing blocked package versions |
| `--enforce-intel` | Enforce intel feed denylist and block matching packages |

## Exit Codes

| Code | Meaning |
|------|---------|
| `0` | Clean — all packages installed |
| `1` | Blocked — CRITICAL or HIGH risk detected |
| `2` | Scan error — download failed or unsupported format |
