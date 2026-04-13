# 种子白名单（Seed Allowlist）

某些包因自身功能需要，可能会访问凭据存储或执行敏感操作。
pipguard 内置种子白名单，可将这些包的结果从 **HIGH** 降到 **MEDIUM**，
从而减少误报导致的硬阻断。

!!! danger "CRITICAL 不会被降级"
    无论是种子白名单还是 `--allow`，都只会把 HIGH 降到 MEDIUM。
    CRITICAL 始终阻断。

## 使用 `--allow`

```bash
pipguard install <package> --allow keyring
```

建议仅在你确认包可信且行为符合预期时使用。
