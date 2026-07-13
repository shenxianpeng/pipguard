# 退出码

pipguard 使用结构化退出码，便于 CI/CD 精准处理。

## `pipguard install`

| 退出码 | 含义 | 触发场景 |
|---|---|---|
| `0` | **Clean**：安装成功 | 所有包为 CLEAN（或 MEDIUM/LOW 已确认） |
| `1` | **Blocked**：已阻断 | 任意包触发 CRITICAL 或 HIGH |
| `2` | **Scan error**：扫描失败 | 下载失败、归档不支持、磁盘异常等 |

## `pipguard scan-feed`

`scan-feed` 是初筛工具，退出码含义不同——`1` 表示"发现需核查的候选"，不是"已阻断"：

| 退出码 | 含义 | 触发场景 |
|---|---|---|
| `0` | **无需核查** | 没有被扫的发布达到或超过 `--min-level` |
| `1` | **发现核查候选** | 至少一个发布达到或超过 `--min-level`（便于定时任务告警） |
| `2` | **Feed 错误** | 无法拉取 feed，或没有任何条目能下载来扫描 |

## CI 示例

```bash
pipguard install --yes -r requirements.txt
echo "Exit code: $?"
```

```yaml title="GitHub Actions"
- name: Secure dependency install
  run: pipguard install --yes -r requirements.txt
```
