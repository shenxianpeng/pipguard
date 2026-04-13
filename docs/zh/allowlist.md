# 种子允许列表（Seed Allowlist）

某些包因其业务职责会合法访问凭据或执行敏感操作。pipguard 内置一份种子允许列表，用于将这些包的风险从 HIGH 降级为 MEDIUM，以减少误报阻断。

!!! danger "CRITICAL 永不降级"
    种子 allowlist（以及 `--allow`）仅支持 HIGH → MEDIUM。
    CRITICAL 风险始终会被阻断。

## 内置列表

| 包名 | 为什么会访问凭据 |
|---|---|
| `keyring` | 凭据存储库，按设计会读写系统密钥链 |
| `keyrings.alt` | keyring 的替代后端实现 |
| `boto3` | AWS SDK，需读取 `~/.aws/credentials` |
| `botocore` | boto3 的核心依赖库 |

## CLI 用法

```bash
pipguard install --allow boto3,botocore -r requirements.txt
```

仅在确认业务必要时加入 allowlist，并定期审计。
