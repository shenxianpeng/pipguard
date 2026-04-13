---
hide:
  - navigation
  - toc
---

<div class="pg-hero">
  <div class="pg-hero__eyebrow">供应链安全 · Python · 零配置</div>
  <div class="pg-hero__headline">
    在攻击落地之前<br>
    <span>先把它拦下。</span>
  </div>
  <div class="pg-hero__sub">
    <strong>pipguard</strong> 在安装前进行 AST 静态分析。<em>代码尚未执行</em> 即可识别风险。
    无数据库、无网络调用、零配置开箱即用。
  </div>
  <div class="pg-hero__pills">
    <span>✔ 零配置</span>
    <span>✔ 标准库实现</span>
    <span>✔ 安装前拦截</span>
    <span>✔ 支持 CI</span>
  </div>
  <div class="pg-hero__cta">
    <a class="md-button md-button--primary" href="installation/">快速开始</a>
    <a class="md-button" href="how-it-works/">工作原理</a>
  </div>
</div>

## 问题背景

当前 Python 供应链攻击常见于安装阶段触发：恶意包会在 `setup.py`、wheel 的 `.pth`，
或安装后入口中执行隐蔽代码。仅依赖“信誉”或黑名单，往往发现得太晚。

## pipguard 的做法

- 在安装前下载目标包
- 仅做静态分析，不执行包内代码
- 按风险级别输出明确结论，并在高危/严重风险时阻断安装

## 风险级别速览

- **CRITICAL**：立即阻断
- **HIGH**：默认阻断
- **MEDIUM**：提示确认
- **LOW / CLEAN**：默认放行
