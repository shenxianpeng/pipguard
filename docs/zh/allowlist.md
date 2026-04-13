> 本页面提供中文入口，内容将持续完善。

# Seed Allowlist

Some packages legitimately access credential stores or perform sensitive operations
as part of their core purpose. pipguard ships with a seed allowlist that reduces
their finding from HIGH to MEDIUM so they don't cause false-positive blocks.

!!! danger "CRITICAL is never reduced"
    The seed allowlist (and `--allow`) only reduces HIGH → MEDIUM.
    CRITICAL findings always block, regardless of any allowlist entry.

## Built-in Allowlist

| Package | Why it accesses credentials |
|---------|----------------------------|
| `keyring` | Credential storage library — reads/writes system keyring by design |
| `keyrings.alt` | Alternative keyring backends |
| `boto3` | AWS SDK — reads `~/.aws/credentials` for authentication |
| `botocore` | AWS core library (boto3 dependency) |
| `awscli` | AWS CLI — reads `~/.aws/config` |
| `paramiko` | SSH client — reads `~/.ssh/id_rsa` for key-based auth |
| `google-auth` | Google authentication — reads `~/.config/gcloud/` |
| `google-cloud-storage` | Google Cloud SDK |
| `google-cloud-bigquery` | Google Cloud BigQuery |
| `google-cloud-core` | Google Cloud base library |
| `azure-identity` | Azure authentication library |

## Per-Invocation Allowlist

Add packages to the allowlist for a single invocation with `--allow`:

```bash
pipguard install --allow my-internal-auth-lib -r requirements.txt
```

Multiple packages:

```bash
pipguard install --allow pkg-a --allow pkg-b -r requirements.txt
```

## Adding to the Project Allowlist

To suggest adding a package to the built-in seed allowlist, open an issue at
[github.com/shenxianpeng/pipguard](https://github.com/shenxianpeng/pipguard/issues)
with evidence of why the credential access is legitimate.
