# Toolchain Trust

pipguard downloads packages with `python -m pip download`. If that pip trusts a
certificate authority whose private key has leaked, an attacker on the network
path can impersonate pypi.org and swap the packages **before** pipguard scans
them. The scan would then vouch for the attacker's code.

## The eMudhra / emSign incident (October 2026)

The private keys behind eMudhra's emSign intermediates were trivially weak, so
anyone could mint a trusted certificate for any domain, including `pypi.org`.
The root they chain to, **emSign ECC Root CA - G3**
(SHA-256 `86a1ecba089c4a8d3bbe2734c612ba341d813e043cf9e8a862cd5c57a36bbe6b`),
was removed in certifi 2026.10.18/19, pip 26.2.2 and uv 0.13.4.

**Every pip older than 26.2.2 always trusts its own bundled copy of certifi**,
in addition to the system store, so updating the OS alone does not help.
See the [Python Discourse announcement](https://discuss.python.org/t/information-for-python-users-regarding-emudhra-emsign-ca-certificate-security-incident/109576).

## What pipguard does

Before downloading, `pipguard install` inspects the certificates the pip it is
about to run actually trusts:

| What it finds | Result |
|---|---|
| pip's CA bundle contains a compromised root | **Blocked**, exit `2`, with the exact fix command |
| The system OpenSSL store contains it (pip reads it via truststore on **Linux**) | pipguard writes a copy of the store **without** the compromised root, points this run's pip at it (`SSL_CERT_FILE`), re-checks that pip no longer trusts the root, then continues |
| On macOS / Windows pip also asks the OS keychain/store, which pipguard can't filter | Same filtering for OpenSSL users, plus a warning to install OS updates |
| Nothing compromised | Silent, continues |

GitHub's `ubuntu-latest` runners still shipped the root in their system store
when this was written, so the filtering is what lets pip 26.2.2 run safely there.

It checks the certificates rather than the pip version, so distro pips that are
patched to use an updated system store (e.g. Debian's) are not flagged.

- `--require-hashes`: pip verifies every download against your lock file, so a
  swapped package is rejected anyway. The block becomes a warning.
- `--skip-toolchain-check`: skip the check entirely (not recommended).
- `pipguard scan-feed` never installs, so it only warns.

## `pipguard doctor`

Check one or more interpreters without installing anything:

```bash
pipguard doctor
pipguard doctor --python /usr/bin/python3 --python ~/project/.venv/bin/python
```

| Exit code | Meaning |
|---|---|
| `0` | Nothing blocks installs (warnings may be printed) |
| `1` | At least one interpreter's pip can be MITM'd through a compromised CA (plain `pip install`, without pipguard's filtering) |
| `2` | An interpreter could not be inspected |

## Fixing it

Upgrade pip from a **hash-pinned** wheel. The sha256 check makes this safe even
when run through the old, vulnerable pip:

```bash
python -m pip install "pip @ https://files.pythonhosted.org/packages/3f/06/3e4420302363fbb71be3c7f35ce042f54bfca330e3e66b3a2e3c4cca579f/pip-26.2.2-py3-none-any.whl#sha256=fd7f4dfa8190e014013b9f08f3e973f4e4c26ffd179a204895533a7254813a70"
```

pip 26.2.2 needs Python 3.10+. Then update the system store
(`sudo apt-get install --only-upgrade ca-certificates`, `brew upgrade ca-certificates`,
or OS updates) and rebuild container images: Docker's official `python:3.11` /
`python:3.12` images will keep shipping an old pip.

The [GitHub Action](usage.md) does the pip upgrade for you before it installs pipguard.
