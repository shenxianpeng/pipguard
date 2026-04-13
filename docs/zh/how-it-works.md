# 工作原理

pipguard 的核心原则只有一条：**扫描阶段绝不执行目标包代码**。

## 架构流程

```text
pipguard install X
       │
       ▼
pip download --prefer-binary X    ← 仅下载 wheel/sdist，不执行代码
       │
       ▼
检测是否回退到 sdist              ← 若检测到 sdist，默认 exit 2（除非 --allow-sdist）
       │
       ▼
解压归档 (zipfile/tarfile)        ← 只解压，不运行脚本
       │
       ▼
静态 AST 扫描                      ← 规则检测敏感行为与恶意模式
       │
       ▼
风险分级与决策                      ← CRITICAL/HIGH 阻断；其余按策略处理
```

## 为什么更安全

- **零执行面**：安装前不运行 `setup.py`、`.pth` 或任意构建脚本
- **零外部情报依赖**：不依赖漏洞数据库、签名或联网查询
- **可解释结果**：每条告警都对应明确规则与风险原因

## 重点检测对象

- `.pth` 自动执行代码
- 安装阶段网络请求（如 `requests` / `socket`）
- 安装阶段命令执行（如 `os.system`、`subprocess`）
- 混淆载荷（如 `eval(base64.b64decode(...))`）

更多细节请见：[风险等级](risk-levels.md)。
