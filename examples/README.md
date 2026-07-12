# Examples

Copy-paste starting points for running pipguard in your own project.

## `scan-feed-cron.yml` — scheduled PyPI sentinel

A GitHub Actions workflow that runs [`pipguard scan-feed`](https://shenxianpeng.github.io/pipguard/usage/#scanning-the-pypi-feed-reporter-workflow)
on a schedule and opens a GitHub issue when recent PyPI releases are flagged for
review. This turns the reporter workflow into a hands-off sentinel.

**Activate it:**

```bash
mkdir -p .github/workflows
cp examples/scan-feed-cron.yml .github/workflows/pipguard-sentinel.yml
git add .github/workflows/pipguard-sentinel.yml && git commit -m "add pipguard PyPI sentinel"
```

Files under `examples/` are inert — GitHub only runs workflows placed in
`.github/workflows/`.

**Tune it** via the `cron` schedule and the `workflow_dispatch` inputs
(`feed`, `min-level`, `limit`). It needs `issues: write` permission (already set
in the file) so it can open review issues with the built-in `GITHUB_TOKEN`.

Remember: a flagged package is a **candidate for review**, not a confirmed
attack — inspect each one (e.g. via the [PyPI Inspector](https://inspector.pypi.io/))
before acting.
