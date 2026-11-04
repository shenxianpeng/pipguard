# Toolchain Trust

pipguard downloads packages with `python -m pip download`. If that pip trusts a
certificate authority whose private key has leaked, an attacker on the network
path can impersonate pypi.org and swap the packages **before** pipguard scans
them. The scan would then vouch for the attacker's code.

## The eMudhra / emSign incident (October 2026)

The private keys of eight [eMudhra intermediate CAs](https://emudhra.we-have-a-problem.com/)
were trivially weak, so anyone can mint a trusted certificate for any domain,
including `pypi.org`. Those intermediates chain to three roots:

| Root | Trusted by |
|---|---|
| emSign ECC Root CA - G3 | certifi / Mozilla, Apple, Microsoft. Removed in certifi 2026.10.18/19 and **pip 26.2.2** |
| emSign Root TLS CA - G3 | Microsoft |
| AAA Certificate Services (Sectigo) | Apple, Microsoft. Already removed by Mozilla and Chrome |

pip trusts these intermediates if **any** of the stores it uses contains one of those roots:

1. **pip's own bundle.** Every pip older than 26.2.2 always loads its vendored
   certifi, so updating the OS alone does not help.
2. **The OpenSSL system store.** pip 24.2+ asks the system store through
   truststore, and on Linux that means this file.
3. **The OS verifier.** On macOS and Windows, truststore asks the OS
   (keychain / Windows store). On a Mac tested on 2026-10-22, pip 26.2.2
   still accepted a certificate from the compromised CAs this way.

See the [Python Discourse announcement](https://discuss.python.org/t/information-for-python-users-regarding-emudhra-emsign-ca-certificate-security-incident/109576).

## What `pipguard install` does

Before downloading, it inspects the certificates the pip it is about to run
actually trusts, fixes what it can **for this run**, and re-checks:

| What it finds | What pipguard does |
|---|---|
| A bad root in pip's own bundle (pip < 26.2.2) | **Blocks**, exit `2`, and prints the hash-pinned fix. Nothing outside pip can fix this |
| A bad root in the OpenSSL store | Writes a copy of the store **without** the bad roots and points the run at it (`SSL_CERT_FILE`). Other CAs, such as a corporate proxy CA, keep working |
| A bad root in the macOS keychain / Windows store | Runs pip with `PIP_USE_DEPRECATED=legacy-certs`, so pip uses only its own (clean) bundle |
| Nothing | Continues silently |

GitHub's `ubuntu-latest` runners still shipped emSign ECC Root CA - G3 in
their system store when this was written. The filtering is what makes pip
26.2.2 safe there.

It checks the certificates rather than the pip version, so distro pips that are
patched to use an updated system store (e.g. Debian's) are not flagged.

- `--require-hashes`: pip verifies every download against your lock file, so a
  swapped package is rejected anyway. The block becomes a warning.
- `--skip-toolchain-check`: skip all of this (not recommended).
- `pipguard scan-feed` never installs, so it only warns.
- With `legacy-certs`, pip ignores CAs that exist only in your OS store (e.g. a
  corporate TLS proxy). Give pip that CA with `--cert` / `PIP_CERT`, or update
  your OS so the bad roots are gone.

## `pipguard doctor`

Shows what **plain** `pip install` trusts, without installing anything:

```bash
pipguard doctor
pipguard doctor --python /usr/bin/python3 --python ~/project/.venv/bin/python

# Ground truth: have pip connect to the incident's test hosts, both as plain
# pip and as pipguard runs it
pipguard doctor --online
```

`--online` connects to `*.we-have-a-problem.com`, the hosts the incident
reporters run with certificates from the compromised CAs. `rejected` is the
safe result.

| Exit code | Meaning |
|---|---|
| `0` | Plain pip does not trust the compromised CAs |
| `1` | Plain pip trusts them (pipguard install may still be protected, see the output) |
| `2` | An interpreter could not be inspected |

## Fixing it for good

Upgrade pip from a **hash-pinned** wheel. The sha256 check makes this safe even
when run through the old, vulnerable pip:

```bash
python -m pip install "pip @ https://files.pythonhosted.org/packages/3f/06/3e4420302363fbb71be3c7f35ce042f54bfca330e3e66b3a2e3c4cca579f/pip-26.2.2-py3-none-any.whl#sha256=fd7f4dfa8190e014013b9f08f3e973f4e4c26ffd179a204895533a7254813a70"
```

pip 26.2.2 needs Python 3.10+. Then update the system store
(`sudo apt-get install --only-upgrade ca-certificates`, `brew upgrade ca-certificates`,
OS updates) and rebuild container images. Docker's official `python:3.11` and
`python:3.12` images will keep shipping an old pip.

The GitHub Action does the pip upgrade for you before it installs pipguard.
