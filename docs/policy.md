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
