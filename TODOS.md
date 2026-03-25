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
