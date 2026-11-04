---
hide:
  - navigation
  - toc
---

<div class="pg-hero">
  <div class="pg-hero__eyebrow">供应链安全 · Python · 零配置</div>
  <div class="pg-hero__headline">
    拦截攻击<br>
    <span class="pg-accent">在落地之前。</span>
  </div>
  <p class="pg-hero__sub">
    <strong>pipguard</strong> 在代码执行前，先通过 AST 扫描每一个包。
    无数据库、无网络调用、无复杂配置 —— 像门卫一样先拦后装。
  </p>
  <div class="pg-hero__facts">
    <span class="pg-hero__fact">零配置</span>
    <span class="pg-hero__fact">纯标准库</span>
    <span class="pg-hero__fact">安装前阻断</span>
    <span class="pg-hero__fact">CI 友好</span>
  </div>
  <div class="pg-cta-group">
    <a class="pg-btn pg-btn-primary" href="installation/">pip install pipguard</a>
    <a class="pg-btn pg-btn-secondary" href="usage/">阅读文档 →</a>
  </div>
</div>

<div class="pg-terminal">
  <div class="pg-terminal__bar">
    <div class="pg-terminal__dot"></div>
    <div class="pg-terminal__dot"></div>
    <div class="pg-terminal__dot"></div>
    <span class="pg-terminal__title">bash — pipguard</span>
  </div>
  <div class="pg-terminal__body">
    <div><span class="t-dollar">$</span><span class="t-cmd">pipguard install litellm==1.82.8</span></div>
    <div>&nbsp;</div>
    <div><span class="t-muted">→ 下载 wheel（不执行代码）</span></div>
    <div><span class="t-muted">→ 解压归档</span></div>
    <div><span class="t-muted">→ AST 扫描 47 个文件</span></div>
    <div>&nbsp;</div>
    <div><span class="t-dim">&nbsp; setup.py&nbsp;&nbsp;&nbsp;&nbsp;&nbsp;&nbsp;&nbsp;&nbsp;&nbsp; ............... </span><span class="t-ok">CLEAN</span></div>
    <div><span class="t-dim">&nbsp; utils/loader.py&nbsp; ............... </span><span class="t-ok">CLEAN</span></div>
    <div><span class="t-dim">&nbsp; .pth files&nbsp;&nbsp;&nbsp;&nbsp;&nbsp;&nbsp; ............... </span><span class="t-block">CRITICAL</span></div>
    <div>&nbsp;</div>
    <div><span class="t-dim">&nbsp; ─────────────────────────────────────</span></div>
    <div>&nbsp;</div>
    <div><span class="t-block">&nbsp; ✗ 已阻断: litellm==1.82.8</span></div>
    <div><span class="t-dim">&nbsp; .pth 自动执行 · 读取 ~/.ssh/id_rsa</span></div>
    <div><span class="t-dim">&nbsp; 并外传到 44.202.x.x:4444</span></div>
    <div>&nbsp;</div>
    <div><span class="t-accent">&nbsp; 风险等级: CRITICAL · 退出码: 1</span></div>
  </div>
</div>

## 问题背景

2026 年 3 月的 litellm 供应链攻击（每月约 9700 万下载）在 `.pth` 文件内嵌入 Python 代码。
该代码会在解释器启动时自动执行，并在一次 `pip install` 后窃取 SSH 密钥、AWS 凭据和 Kubernetes 配置。

传统工具（如 pip-audit、GuardDog）通常依赖已知签名或漏洞库，面对零日投毒可能失效。
pipguard 的问题更直接：

!!! danger "传统工具经常不会问的问题"
    某个 `pip install` 是否应该读取 `~/.ssh/id_rsa`？

    答案是 **不应该**，而且这个判断不需要任何在线数据库。

## 工作方式

<div class="pg-steps">
  <div class="pg-step">
    <div class="pg-step__num">01</div>
    <div class="pg-step__title">pip download</div>
    <div class="pg-step__desc">只下载 wheel 或 sdist。<br>绝不执行代码。</div>
  </div>
  <div class="pg-step">
    <div class="pg-step__num">02</div>
    <div class="pg-step__title">Sdist 检测</div>
    <div class="pg-step__desc">检测到 sdist 默认 exit 2（不安全）。</div>
  </div>
  <div class="pg-step">
    <div class="pg-step__num">03</div>
    <div class="pg-step__title">解压</div>
    <div class="pg-step__desc">仅使用 zipfile/tarfile。<br>不调用 subprocess，不 exec。</div>
  </div>
  <div class="pg-step">
    <div class="pg-step__num">04</div>
    <div class="pg-step__title">AST 扫描</div>
    <div class="pg-step__desc">并行扫描全部 .py 文件；对 .pth、setup.py 提升敏感度。</div>
  </div>
  <div class="pg-step">
    <div class="pg-step__num">05</div>
    <div class="pg-step__title">风险决策</div>
    <div class="pg-step__desc">CRITICAL/HIGH 阻断（exit 1）；CLEAN 直接安装。</div>
  </div>
</div>

## 风险等级速览

| 等级 | 触发条件示例 | 处理 |
|-------|-----------------|--------|
| <span class="pg-badge pg-badge-critical">CRITICAL</span> | `.pth` 可执行代码；`eval(base64.b64decode(...))` | 阻断（exit 1） |
| <span class="pg-badge pg-badge-high">HIGH</span> | 同形异义包名；安装钩子读取 `~/.ssh`/`~/.aws`；`shell=True`；`os.system()` | 阻断（exit 1） |
| <span class="pg-badge pg-badge-medium">MEDIUM</span> | 二进制-only wheel；运行期网络调用；敏感环境变量 | 告警 + 确认 |
| LOW | 混合型二进制扩展；动态导入 | 告警 + 确认 |
| CLEAN | 无风险命中 | 直接安装 |

[查看完整风险等级说明 →](risk-levels.md)
