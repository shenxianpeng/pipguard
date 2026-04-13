> 本页面提供中文入口，内容将持续完善。

# Installation

## Requirements

- Python 3.10+
- pip (any recent version)
- Zero external dependencies — pipguard uses only the Python standard library

## Install from PyPI

```bash
pip install pipguard
```

Verify the installation:

```bash
pipguard --version
```

## Install from Source

```bash
git clone https://github.com/shenxianpeng/pipguard.git
cd pipguard
pip install -e .
```

## CI / Docker

Add to your `requirements-dev.txt` or install directly in your CI pipeline:

```yaml title=".github/workflows/ci.yml"
- name: Install pipguard
  run: pip install pipguard

- name: Secure dependency install
  run: pipguard install --yes -r requirements.txt
```

## Upgrading

```bash
pip install --upgrade pipguard
```

## Uninstalling

```bash
pip uninstall pipguard
```

pipguard creates no configuration files and leaves no persistent state — uninstall is clean.
