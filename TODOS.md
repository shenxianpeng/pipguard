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

## TODO-4: Document `--allow-sdist` Security Semantics

**What:** README and `--help` currently say "WARNING: reduces security guarantee". In fact, `--allow-sdist` **destroys** the security guarantee, not merely weakens it. Even though pipguard runs AST scanning on Python source files, `pip install` will still execute arbitrary code in `setup.py` / build-backend during installation. AST scanning only covers the **static content** of setup.py and cannot prevent runtime-generated payloads.

**Why:** Users seeing "reduces security guarantee" may mistakenly believe scanning still provides partial protection. In reality: sdist install = code execution, and pipguard cannot prevent it. A false sense of security is more dangerous than no protection at all.

**Proposed fix:**
- Upgrade the `--allow-sdist` warning in README to explicitly state: "sdist install executes arbitrary code. pipguard's AST scan does NOT prevent this."
- Sync `--help` text accordingly
- Consider renaming `--allow-sdist` to `--allow-code-execution` to force users to acknowledge the risk

**Depends on:** None
**Priority:** v0.1.x (documentation fix, ship with next patch release)

---

## TODO-5: Gate Behavior Decision for Binary-Only Packages

**What:** Currently, binary-only packages (wheels with no `.py` source) are shown as `[UNKNOWN]` but their `effective_level = CLEAN`, the gate does not block, and installation continues silently. This is fail-open behavior.

**Why:** pipguard's core promise is "scan before install". Binary-only packages cannot be AST-scanned at all — they are the most opaque package type, and simultaneously the most dangerous. Marking them as CLEAN and silently installing contradicts this promise.

**Options to decide:**
- A) `binary-only` → `effective_level = MEDIUM` → triggers confirmation prompt (skippable with `--yes`)
- B) `binary-only` → blocked by default, requires `--allow-binary-only` to explicitly allow
- C) Keep current behavior (user sees UNKNOWN warning and decides)

**Current state:** TODO-1 (.so scanning) will add a LOW finding for binary-only packages, at which point the gate will trigger a prompt. Can be decided together when TODO-1 is done.

**Depends on:** TODO-1 (.so scanning)
**Priority:** v0.2

---
