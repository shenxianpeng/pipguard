# Policy as Code

pipguard can load an optional policy file to enforce organization-wide defaults.

Default path:

```text
./pipguard.toml
```

Or pass explicitly:

```bash
pipguard install --policy ./security/pipguard.toml -r requirements.txt
```

## Example

```toml
[install]
require_hashes = true
allow_vcs_pinned = true
allow_direct_url_pinned = true
binary_only = "block"  # prompt | block | allow

[allowlist]
seed = ["my-internal-auth-lib", "corp-keyring"]

[intel]
feed = "https://example.org/pipguard-feed.json"
enforce = true

[osv]
enabled = true        # query OSV.dev for known CVEs (same as --check-vulns)
fail_on_vuln = false  # if true, a known CVE fails the install (same as --fail-on-vuln)
```

## Keys

- `require_hashes` (bool): enforce hash-locked dependencies.
- `allow_vcs_pinned` (bool): allow VCS requirements only when pinned to commit hash.
- `allow_direct_url_pinned` (bool): allow direct URL dependencies only with hash fragment.
- `binary_only` (string): behavior when binary-only wheel is detected:
  - `prompt` (default): keep MEDIUM behavior.
  - `block`: fail installation (exit 1).
  - `allow`: do not enforce additional binary-only policy block.

`[intel]` section:

- `feed` (string): local file path or HTTPS URL to a JSON denylist feed.
- `enforce` (bool): if `true`, block packages in the feed before scan/install.

`[allowlist]` section:

- `seed` (list[string]): project-level seed allowlist entries. These are merged with
  the built-in seed allowlist and `--allow` CLI flags.

`[osv]` section:

- `enabled` (bool): query [OSV.dev](https://osv.dev) for known CVEs (equivalent to
  `--check-vulns`). Off by default — this is the only outbound network call pipguard
  makes during a scan.
- `fail_on_vuln` (bool): if `true`, a package with a known CVE fails the install
  (equivalent to `--fail-on-vuln`); implies `enabled`. Informational otherwise.

CLI flags take precedence over the policy file, which takes precedence over the
built-in defaults.
