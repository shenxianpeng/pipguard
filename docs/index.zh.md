---
template: landing.html
title: pipguard
hero:
  eyebrow: 供应链安全 · Python · 零配置
  title: "拦截攻击<br>*在落地之前。*"
  text: >-
    **pipguard** 在代码执行前，先通过 AST 扫描每一个包。
    无数据库、无网络调用、无复杂配置 —— 像门卫一样先拦后装。
  actions:
    - {text: pip install pipguard, link: installation.md, icon: download, primary: true}
    - {text: 阅读文档, link: usage.md, icon: book-open}
  code:
    title: bash — pipguard
    lang: text
    content: |
      $ pipguard install litellm==1.82.8

      → 下载 wheel（不执行代码）
      → 解压归档
      → AST 扫描 47 个文件

        setup.py          ............... CLEAN
        utils/loader.py   ............... CLEAN
        .pth files        ............... CRITICAL

        ─────────────────────────────────────

        ✗ 已阻断: litellm==1.82.8
        .pth 自动执行 · 读取 ~/.ssh/id_rsa
        并外传到 44.202.x.x:4444

        风险等级: CRITICAL · 退出码: 1
sections:
  - type: features
    columns: 4
    items:
      - {icon: sliders-horizontal, title: 零配置}
      - {icon: package, title: 纯标准库}
      - {icon: shield-x, title: 安装前阻断}
      - {icon: workflow, title: CI 友好}
  - type: content
---

## 问题背景 {#the-problem}

2026 年 3 月的 litellm 供应链攻击（每月约 9700 万下载）在 `.pth` 文件内嵌入 Python 代码。
该代码会在解释器启动时自动执行，并在一次 `pip install` 后窃取 SSH 密钥、AWS 凭据和 Kubernetes 配置。

传统工具（如 pip-audit、GuardDog）通常依赖已知签名或漏洞库，面对零日投毒可能失效。
pipguard 的问题更直接：

!!! danger "传统工具经常不会问的问题"
    某个 `pip install` 是否应该读取 `~/.ssh/id_rsa`？

    答案是 **不应该**，而且这个判断不需要任何在线数据库。

## 工作方式 {#how-it-works}

1. pip download

    只下载 wheel 或 sdist。绝不执行代码。

2. Sdist 检测

    检测到 sdist 默认 exit 2（不安全）。

3. 解压

    仅使用 zipfile/tarfile。不调用 subprocess，不 exec。

4. AST 扫描

    并行扫描全部 .py 文件；对 .pth、setup.py 提升敏感度。

5. 风险决策

    CRITICAL/HIGH 阻断（exit 1）；CLEAN 直接安装。
{.steps}

## 风险等级速览 {#risk-levels-at-a-glance}

| 等级 | 触发条件示例 | 处理 |
|-------|-----------------|--------|
| **CRITICAL**{.badge .caution} | `.pth` 可执行代码；`eval(base64.b64decode(...))` | 阻断（exit 1） |
| **HIGH**{.badge .warning} | 同形异义包名；安装钩子读取 `~/.ssh`/`~/.aws`；`shell=True`；`os.system()` | 阻断（exit 1） |
| **MEDIUM**{.badge .note} | 二进制-only wheel；运行期网络调用；敏感环境变量 | 告警 + 确认 |
| LOW | 混合型二进制扩展；动态导入 | 告警 + 确认 |
| CLEAN | 无风险命中 | 直接安装 |

[查看完整风险等级说明 →](risk-levels.md)
