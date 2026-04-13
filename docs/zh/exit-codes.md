# 退出码

pipguard 使用结构化退出码，便于 CI/CD 精准处理。

| 退出码 | 含义 | 触发场景 |
|---|---|---|
| `0` | **Clean**：安装成功 | 所有包为 CLEAN（或 MEDIUM/LOW 已确认） |
| `1` | **Blocked**：已阻断 | 任意包触发 CRITICAL 或 HIGH |
| `2` | **Scan error**：扫描失败 | 下载失败、归档不支持、磁盘异常等 |

## CI 示例

```bash
pipguard install --yes -r requirements.txt
echo "Exit code: $?"
```

```yaml title="GitHub Actions"
- name: Secure dependency install
  run: pipguard install --yes -r requirements.txt
```
