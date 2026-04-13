# 策略即代码（Policy as Code）

pipguard 支持加载可选策略文件，用于在团队或组织范围内统一安全默认值。

默认路径：

```text
./pipguard.toml
```

也可以显式指定：

```bash
pipguard install --policy ./security/pipguard.toml -r requirements.txt
```

## 示例

```toml title="pipguard.toml"
[install]
yes = true
allow_sdist = false

[allowlist]
packages = ["boto3", "botocore"]
```

## 建议

- 在 CI 中强制使用同一份策略文件
- 仅将确有业务必要的包加入 allowlist
- 对策略改动走代码评审流程
