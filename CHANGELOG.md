# Changelog

All notable changes to pipguard are documented here.
Format follows [Keep a Changelog](https://keepachangelog.com/en/1.0.0/).

---

## [0.1.0] - 2026-03-25

### Added

- **Phase 1 MVP: pre-install static scanner**
  - `pipguard install <package>` — download, scan, and install a Python package
  - `pipguard install -r requirements.txt` — scan an entire requirements file
  - AST-based scanner with four risk levels: CRITICAL, HIGH, MEDIUM, LOW
  - `.pth` executable content detection (catches the litellm 1.82.8 attack vector)
  - `eval(base64.b64decode(...))` obfuscated payload detection (CRITICAL)
  - Credential path detection (`~/.ssh`, `~/.aws`, `~/.kube`, etc.) scoped by install hook vs. runtime
  - Network call detection in install hooks (CRITICAL) vs. runtime code (MEDIUM)
  - `subprocess shell=True` detection in install hooks (HIGH)
  - Sensitive env var access detection (MEDIUM)
  - Dynamic import detection (LOW)
  - Parallel scanning via `concurrent.futures.ThreadPoolExecutor` (Amendment A8)
  - TOCTOU-safe installation via `pip install --no-index --find-links` (Amendment A2)
  - sdist detection by file extension — blocks silent `--prefer-binary` fallback (Amendment A1)
  - Seed allowlist of 10 packages (boto3, keyring, paramiko, etc.) — reduces HIGH→MEDIUM
  - CRITICAL findings never reduced by allowlist (Amendment A3)
  - `--yes`/`-y` flag for CI mode (no prompts, still exits 1 on CRITICAL/HIGH)
  - `--force` flag for known false-positives (escape hatch, logs a warning)
  - `--allow <pkg>` flag for per-invocation allowlist additions
  - `--allow-sdist` flag to opt into sdist scanning (with explicit warning)
  - Guaranteed temp dir cleanup via `atexit` + SIGINT handler (Amendment A9)
  - Disk space check before download (Amendment A10)
  - Exit codes: 0 = clean, 1 = blocked, 2 = scan error
  - Zero external dependencies — pure Python stdlib (Amendment A7)
- **Test suite**: 74 tests covering all risk levels, allowlist logic, CLI parsing, and fixtures
  - `tests/fixtures/pth_attack/litellm_attack.pth` — the actual March 2026 attack pattern
  - `tests/fixtures/clean_pkg/` — known-clean package for false-positive regression testing
- **README.md** with usage guide, risk level table, ASCII architecture diagram
- **TODOS.md** with deferred items (binary extension scanning, homoglyph normalization, real-time intel)
- **pyproject.toml** updated with CLI entry point (`pipguard`), classifiers, pytest config
- **.gitignore** for Python artifacts

### Changed

- `pipguard/__init__.py`: replaced stub `hello()` with version `0.1.0` and package docstring
- `pyproject.toml`: corrected author email, added description, entry point, classifiers

## [0.0.1] - 2026-03-25

### Added

- Initial PyPI stub release (name reservation)
- `pipguard/__init__.py` placeholder
- `.github/workflows/publish.yml` — OIDC trusted publishing to PyPI on version tags
