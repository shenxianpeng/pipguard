> 本页面提供中文入口，内容将持续完善。

---
hide:
  - navigation
  - toc
---

<div class="pg-hero">
  <div class="pg-hero__eyebrow">supply chain security · python · zero config</div>
  <div class="pg-hero__headline">
    Block the attack<br>
    <span class="pg-accent">before it lands.</span>
  </div>
  <p class="pg-hero__sub">
    <strong>pipguard</strong> scans every package via AST analysis <em>before</em> code runs.
    No database. No network calls. No configuration. Just a guard at the door.
  </p>
  <div class="pg-hero__facts">
    <span class="pg-hero__fact">Zero config</span>
    <span class="pg-hero__fact">Pure stdlib</span>
    <span class="pg-hero__fact">Blocks before install</span>
    <span class="pg-hero__fact">CI-ready</span>
  </div>
  <div class="pg-cta-group">
    <a class="pg-btn pg-btn-primary" href="installation/">pip install pipguard</a>
    <a class="pg-btn pg-btn-secondary" href="usage/">Read the docs →</a>
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
    <div><span class="t-muted">→ Downloading wheel (no code executed)</span></div>
    <div><span class="t-muted">→ Extracting archive</span></div>
    <div><span class="t-muted">→ AST scanning 47 files</span></div>
    <div>&nbsp;</div>
    <div><span class="t-dim">&nbsp; setup.py&nbsp;&nbsp;&nbsp;&nbsp;&nbsp;&nbsp;&nbsp;&nbsp;&nbsp; ............... </span><span class="t-ok">CLEAN</span></div>
    <div><span class="t-dim">&nbsp; utils/loader.py&nbsp; ............... </span><span class="t-ok">CLEAN</span></div>
    <div><span class="t-dim">&nbsp; .pth files&nbsp;&nbsp;&nbsp;&nbsp;&nbsp;&nbsp; ............... </span><span class="t-block">CRITICAL</span></div>
    <div>&nbsp;</div>
    <div><span class="t-dim">&nbsp; ─────────────────────────────────────</span></div>
    <div>&nbsp;</div>
    <div><span class="t-block">&nbsp; ✗ BLOCKED: litellm==1.82.8</span></div>
    <div><span class="t-dim">&nbsp; .pth autorun · reads ~/.ssh/id_rsa</span></div>
    <div><span class="t-dim">&nbsp; exfiltrates to 44.202.x.x:4444</span></div>
    <div>&nbsp;</div>
    <div><span class="t-accent">&nbsp; Severity: CRITICAL · Exit code: 1</span></div>
  </div>
</div>

## The Problem

The March 2026 litellm attack (97M downloads/month) embedded Python code in a `.pth`
file — executed automatically at interpreter startup, exfiltrating SSH keys, AWS credentials,
and Kubernetes configs from a single `pip install`.

Classical tools (pip-audit, GuardDog) are blind to zero-day attacks. They check known
signatures. pipguard asks a different question:

!!! danger "The question classical tools never ask"
    Should **any** `pip install` be allowed to read `~/.ssh/id_rsa`?

    The answer is **no**. And that question doesn't require a database.

## How It Works

<div class="pg-steps">
  <div class="pg-step">
    <div class="pg-step__num">01</div>
    <div class="pg-step__title">pip download</div>
    <div class="pg-step__desc">Downloads wheel or sdist.<br>No code runs. Ever.</div>
  </div>
  <div class="pg-step">
    <div class="pg-step__num">02</div>
    <div class="pg-step__title">Sdist check</div>
    <div class="pg-step__desc">Exit 2 if sdist detected — build scripts are unsafe.</div>
  </div>
  <div class="pg-step">
    <div class="pg-step__num">03</div>
    <div class="pg-step__title">Extract</div>
    <div class="pg-step__desc">zipfile/tarfile only.<br>No subprocess. No exec.</div>
  </div>
  <div class="pg-step">
    <div class="pg-step__num">04</div>
    <div class="pg-step__title">AST scan</div>
    <div class="pg-step__desc">Parallel scan of all .py files. CRITICAL scope on .pth, setup.py.</div>
  </div>
  <div class="pg-step">
    <div class="pg-step__num">05</div>
    <div class="pg-step__title">Risk score</div>
    <div class="pg-step__desc">CRITICAL/HIGH → exit 1.<br>CLEAN → install silently.</div>
  </div>
</div>

## Risk Levels at a Glance

| Level | What triggers it | Action |
|-------|-----------------|--------|
| <span class="pg-badge pg-badge-critical">CRITICAL</span> | `.pth` executable code; `eval(base64.b64decode(...))` | Block (exit 1) |
| <span class="pg-badge pg-badge-high">HIGH</span> | Non-ASCII package name (homoglyph); reads `~/.ssh`, `~/.aws` in install hooks; `shell=True`; `os.system()` | Block (exit 1) |
| <span class="pg-badge pg-badge-medium">MEDIUM</span> | Binary-only wheel; network in runtime; sensitive env vars | Warn + confirm |
| LOW | Compiled binary extension in mixed wheel; dynamic imports | Warn + confirm |
| CLEAN | None of the above | Install silently |

[Full risk level reference →](risk-levels.md)
