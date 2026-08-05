# Security Policy

pipguard is a security tool, so we hold its own supply chain and code to the
same bar we ask of the packages it scans.

## Reporting a vulnerability

**Please do not open a public issue for security vulnerabilities.**

Report privately via GitHub's [private vulnerability reporting](https://github.com/shenxianpeng/pipguard/security/advisories/new)
(Security → Report a vulnerability), or email **xianpeng.shen@gmail.com**.

Please include:

- a description of the issue and its impact,
- the pipguard version and Python version,
- steps to reproduce (a minimal package or requirements file is ideal).

### What to expect

- **Acknowledgement** within 72 hours.
- An initial assessment and severity within 7 days.
- Coordinated disclosure: we will agree on a timeline with you and credit you
  in the release notes and advisory unless you prefer to remain anonymous.

## Scope

In scope — vulnerabilities **in pipguard itself**, for example:

- a crafted package that executes code while pipguard is *scanning* it
  (pipguard must never run package code — extraction is `zipfile`/`tarfile`
  only, scanning is AST-only),
- a **scan bypass**: a malicious pattern that pipguard should flag but doesn't
  (false negative) — these are the most valuable reports,
- a way to make the install gate fail open (proceed when it should block).

Out of scope:

- known limitations documented in [How It Works → Limitations](https://shenxianpeng.github.io/pipguard/how-it-works/#limitations)
  and the [Runtime Sandbox](https://shenxianpeng.github.io/pipguard/runtime-sandbox/)
  page (e.g. payloads inside compiled `.so`/`.pyd` extensions, post-install
  first-import autorun) — these are acknowledged gaps, not vulnerabilities;
- vulnerabilities in third-party packages pipguard scans (report those to the
  package maintainer, or via the [reporter workflow](https://shenxianpeng.github.io/pipguard/usage/#scanning-the-pypi-feed-reporter-workflow)).

A false negative that lets a real install-time attack through the gate **is** in
scope and we want to hear about it.

## Supply chain of pipguard itself

- **Zero third-party runtime dependencies** (pure Python standard library), so
  pipguard adds no transitive attack surface to your environment.
- Releases are published to PyPI via **Trusted Publishing (OIDC)** with **PEP 740
  build provenance / attestations** — no long-lived API token, and each artifact
  is verifiably built from this repository's tagged source.
- Detection is guarded by a **CI-enforced benchmark** (TPR 100% / FPR 0% on the
  checked-in corpus); a regression that weakens detection fails the build.

## Supported versions

pipguard is pre-1.0; security fixes land on the latest released version. Pin a
version and upgrade promptly.
