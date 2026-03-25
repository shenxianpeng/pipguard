# pipguard — TODOS

Deferred items from /plan-eng-review on 2026-03-25. Each item has enough context
to be actionable months from now.

---

## TODO-1: C Extension / Binary .so Scanning

**What:** Add detection and warning for wheels containing compiled binary extensions
(`.so`, `.pyd`, `.dylib`). Phase 1 AST scanning is completely blind to payloads
embedded in compiled code.

**Why:** A motivated attacker aware of pipguard will put their payload in a `.so` file.
This is a known architectural ceiling of static AST scanning.

**Current state:** Phase 1 marks wheels with no `.py` source as UNKNOWN (warning).
But wheels with BOTH `.py` source AND `.so` extensions are not flagged specially —
the AST scan runs on the Python parts and misses the binary parts.

**Proposed fix:**
- In the extractor, enumerate all files in the wheel
- If any `.so`/`.pyd` file is found, add a LOW finding: "wheel contains compiled
  binary extension at {path} — cannot inspect for malicious code"
- For wheels with ONLY binary extensions and no `.py` source, escalate to MEDIUM

**Depends on:** Phase 1 implementation
**Priority:** v0.2 (after Phase 1 ships)

---

## TODO-2: Homoglyph / Unicode Package Name Attack

**What:** Normalize package names before allowlist comparison using Unicode NFKC
normalization + ASCII-only enforcement. A package name `bото3` (with Cyrillic `о`)
is visually identical to `boto3` but string-comparison-different.

**Why:** Allowlist reduces HIGH → MEDIUM for trusted packages. If an attacker publishes
a visually identical package that mimics boto3's credential access patterns, the allowlist
won't protect them (exact match fails) — but the user might trust it due to visual
similarity. The real risk is in the UI: pipguard should detect lookalike names and flag
them regardless of allowlist status.

**Proposed fix:**
- Normalize all package names (both input and allowlist) with `unicodedata.normalize('NFKC', name)`
- Flag any package name containing non-ASCII characters as a HIGH finding:
  "package name contains non-ASCII characters — possible homoglyph attack"
- PyPI technically disallows non-ASCII in normalized names, but this can be a defense
  in depth check

**Depends on:** Phase 1 allowlist implementation
**Priority:** v0.2

---

## TODO-3: Real-time Attack Intelligence Push

**What:** A lightweight mechanism to notify pipguard users of newly discovered supply
chain attacks within minutes of discovery (vs hours/days for CVE database updates).

**Why:** The litellm attack was live for <1 hour. CVE databases wouldn't have caught it.
A community-driven intelligence feed that distributes new attack signatures (package name,
version, indicator of compromise) would let pipguard users block newly discovered attacks
in near-real-time — this is the "10x version" from office hours.

**Components:**
- A public feed format (lightweight JSON over HTTPS, or RSS)
- A signature update mechanism in pipguard (`pipguard update-rules` or auto-check on install)
- A community contribution flow (PR to a rules repo triggers signing + publishing)
- Possible sources to research: GuardDog rule sets, OSV database (osv.dev), PyPI
  malware reports API

**Research first:** Check if `osv.dev` or PyPI's own malware report API provides a
real-time feed that could be consumed without building the infrastructure from scratch.

**Depends on:** Phase 1 shipped, community traction established
**Priority:** v0.3 / post-launch

---

## TODO-4: --allow-sdist 安全语义文档化

**What:** README 和 `--help` 当前说 "WARNING: reduces security guarantee"。实际上 `--allow-sdist` **销毁**了安全保证，不只是弱化。即使 pipguard 对 Python 源文件运行了 AST 扫描，`pip install` 在安装阶段仍会执行 `setup.py` / build-backend 中的任意代码。AST 扫描只覆盖了 setup.py 的**静态内容**，无法防止运行时动态生成的载荷。

**Why:** 用户看到 "reduces security guarantee" 可能误以为扫描仍然提供部分保护。实际上：sdist 安装 = 代码执行，pipguard 无法阻止。错误的安全感比没有保护更危险。

**Proposed fix:**
- README 中将 `--allow-sdist` 警告升级为明确声明："sdist install executes arbitrary code. pipguard's AST scan does NOT prevent this."
- `--help` 文本同步更新
- 考虑将 `--allow-sdist` 重命名为 `--allow-code-execution` 以强制用户意识到风险

**Depends on:** 无
**Priority:** v0.1.x（文档修复，随下个 patch 版本发布）

---

## TODO-5: binary-only 包的闸道行为决策

**What:** 当前 binary-only 包（无 .py 源码的 wheel）显示为 `[UNKNOWN]`，但其 `effective_level = CLEAN`，闸道逻辑不阻断，安装静默继续。这是 fail-open 行为。

**Why:** pipguard 的核心承诺是"扫描后才安装"。binary-only 包完全无法被 AST 扫描——它们是最不透明的包类型，同时也是最危险的。将其标为 CLEAN 并静默安装与这个承诺矛盾。

**Options to decide:**
- A) `binary-only` → `effective_level = MEDIUM` → 触发确认提示（--yes 可跳过）
- B) `binary-only` → 默认阻断，需 `--allow-binary-only` 显式允许
- C) 保持现状（用户看到 UNKNOWN 警告后自行决定）

**Current state:** TODO-1 (.so 扫描) 将为 binary-only 包增加 LOW finding，届时 gate 会触发提示。可等 TODO-1 完成后一并决定。

**Depends on:** TODO-1（.so 扫描）
**Priority:** v0.2

---
