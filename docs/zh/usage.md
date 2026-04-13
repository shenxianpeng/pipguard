# 用法

![pipguard 演示](../assets/demo.gif)

## 基础命令

### 安装单个包（先扫描）

```bash
pipguard install requests
```

### 安装多个包

```bash
pipguard install requests flask pydantic
```

### 使用 requirements 文件

```bash
pipguard install -r requirements.txt
```

## 常见参数

- `--allow <name>`：降低指定包的阻断级别（仅 HIGH → MEDIUM）
- `--yes`：对可确认项自动同意
- `--json`：输出 JSON 结果，便于 CI/平台处理

## 推荐流程

1. 在本地或 CI 中先跑 `pipguard install ...`
2. 出现 HIGH/CRITICAL 时阻断并排查
3. 必要时通过策略文件统一组织级规则
