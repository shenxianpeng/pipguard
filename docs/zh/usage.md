# 使用说明

![pipguard 演示](assets/demo.gif)

## 基本用法

### 安装单个包

```bash
pipguard install requests
```

pipguard 会先下载并扫描，确认安全后再安装。若无风险，输出会非常简洁。

### 从 requirements.txt 安装

```bash
pipguard install -r requirements.txt
```

### 非交互模式（CI 推荐）

```bash
pipguard install --yes -r requirements.txt
```

## 常用参数

- `--yes`：自动确认 MEDIUM/LOW 风险（适合 CI）
- `--allow pkg1,pkg2`：允许指定包将 HIGH 降级为 MEDIUM
- `--allow-sdist`：允许 sdist（默认不允许）
- `--policy path/to/pipguard.toml`：使用策略文件

## 输出与行为

- 检测到 **CRITICAL/HIGH**：阻断安装，退出码 `1`
- 检测到 **MEDIUM/LOW**：提示确认（或 `--yes` 自动继续）
- 全部 **CLEAN**：静默完成安装，退出码 `0`
- 扫描失败：退出码 `2`

更多细节请参考：[风险等级](risk-levels.md) 与 [退出码](exit-codes.md)。
