# Exit Codes

pipguard uses structured exit codes so CI pipelines can react precisely.

## `pipguard install`

| Code | Meaning | When it occurs |
|------|---------|---------------|
| `0` | **Clean** — install succeeded | All packages scanned as CLEAN (or MEDIUM/LOW with user confirmation) |
| `1` | **Blocked** — CRITICAL or HIGH risk detected | Any package triggered a CRITICAL or HIGH finding |
| `2` | **Scan error** — could not complete the scan | Download failed, unsupported archive format, disk space error |

## `pipguard scan-feed`

`scan-feed` is a triage tool, so its codes differ — exit `1` means "found something
to review", not "blocked":

| Code | Meaning | When it occurs |
|------|---------|---------------|
| `0` | **Nothing to review** | No scanned release met or exceeded `--min-level` |
| `1` | **Review candidates found** | At least one release met or exceeded `--min-level` (so a scheduled job can alert) |
| `2` | **Feed error** | The feed could not be fetched, or no entries could be downloaded to scan |

## Usage in CI

```bash
pipguard install --yes -r requirements.txt
echo "Exit code: $?"
```

```yaml title="GitHub Actions"
- name: Secure dependency install
  run: pipguard install --yes -r requirements.txt
  # Step fails automatically on exit 1 or 2
```

```yaml title="GitLab CI"
install:
  script:
    - pipguard install --yes -r requirements.txt
```

## Distinguishing Exit Codes

If you need to handle scan errors differently from blocked packages:

```bash
pipguard install --yes -r requirements.txt
EXIT=$?
if [ $EXIT -eq 1 ]; then
  echo "Security block — malicious package detected"
  exit 1
elif [ $EXIT -eq 2 ]; then
  echo "Scan error — check network or archive format"
  exit 2
fi
```
