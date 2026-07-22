# Contributing to pipguard

Thank you for your interest in contributing to pipguard! This document provides guidelines
and information for contributors.

## Getting Started

1. **Fork** the repository and clone your fork locally.
2. **Create a branch** for your feature or fix:
   ```bash
   git checkout -b my-feature
   ```
3. **Install development dependencies**:
   ```bash
   pip install -e .
   pip install pytest pytest-cov ruff mypy
   ```

## Development Workflow

### Running Tests

```bash
# Run the full test suite with coverage
make test

# Run a specific test file
pytest tests/test_scanner.py -v

# Run the detection benchmark (TPR/FPR)
make benchmark
```

### Linting and Formatting

```bash
# Check for lint issues
ruff check .

# Auto-fix lint issues
ruff check --fix .

# Format code
ruff format .

# Type checking
mypy pipguard/
```

### Building Documentation

```bash
# Serve docs locally with hot-reload
make docs

# Build static docs
make docs-build
```

## Code Guidelines

- **Zero external dependencies**: pipguard uses only the Python standard library at runtime.
  Development/test dependencies are fine in `pyproject.toml` optional extras.
- **Type hints**: All new functions should include type annotations.
- **Tests**: All new features must include tests. Aim for the existing coverage level or higher.
- **AST scanner rules**: New detection rules should include both a test case and an entry in the
  benchmark corpus (`benchmark/corpus/`) for TPR/FPR regression tracking.

## Pull Request Process

1. Ensure all tests pass: `pytest`
2. Ensure lint passes: `ruff check .`
3. Update documentation if your change affects user-facing behavior.
4. Keep PRs focused — one feature or fix per PR.
5. Write a clear PR description explaining **what** and **why**.

## Architecture Overview

```
pipguard/
├── cli.py          # CLI entry point, argument parsing, subcommands
├── scanner.py      # AST-based static analysis engine
├── models.py       # Data models (Finding, PackageScanResult, RiskLevel)
├── aggregator.py   # Risk aggregation, allowlist, report formatting
├── formatters.py   # JSON/SARIF output formatters
├── downloader.py   # Package download (pip download wrapper)
├── extractor.py    # Archive extraction and file enumeration
├── installer.py    # Safe local install (TOCTOU-resistant)
├── policy.py       # Policy-as-code (pipguard.toml) support
├── osv.py          # OSV.dev vulnerability database queries
├── intel.py        # Threat-intelligence feed support
├── feed.py         # PyPI RSS feed parsing
├── sandbox.py      # Experimental runtime capability sandbox
└── cleanup.py      # Signal handlers and temp dir cleanup
```

## Reporting Issues

- Use [GitHub Issues](https://github.com/shenxianpeng/pipguard/issues) for bugs and feature requests.
- For security vulnerabilities, see [SECURITY.md](SECURITY.md).

## License

By contributing to pipguard, you agree that your contributions will be licensed under the MIT License.
