"""AST-based static scanner for Python package files.

Risk scoring (per design doc + Architecture Amendment A6):

Install-hook scope (setup.py, setup.cfg, pyproject.toml, *.pth):
  CRITICAL  executable .pth content; eval/exec on b64; network calls
  HIGH      credential path reads; subprocess shell=True

Runtime scope (all other .py):
  MEDIUM    network calls; sensitive env var access
  LOW       dynamic importlib; __import__

CLEAN: none of the above.
"""

import ast
import os
import re
from typing import List

from .models import Finding, RiskLevel

# Credential paths that legitimate pip packages should never read
CREDENTIAL_PATHS = [
    "~/.ssh",
    ".ssh/id_rsa",
    ".ssh/id_ed25519",
    ".ssh/id_ecdsa",
    "~/.aws",
    ".aws/credentials",
    "~/.kube",
    ".kube/config",
    "~/.gnupg",
    "~/.config/gcloud",
    "~/.netrc",
    "~/.git-credentials",
]

# Env var names indicating credential access
_SENSITIVE_ENV_RE = re.compile(
    r"(?i)(KEY|TOKEN|SECRET|PASSWORD|CREDENTIAL|PASSWD|API_KEY|ACCESS_KEY)"
)

# Install hook filenames (HIGH severity scope — A6)
_INSTALL_HOOK_NAMES = frozenset({"setup.py", "setup.cfg", "pyproject.toml"})

# Network-call function names
_NETWORK_FUNCS = frozenset({
    "socket.connect",
    "socket.create_connection",
    "requests.get",
    "requests.post",
    "requests.put",
    "requests.patch",
    "requests.delete",
    "requests.request",
    "urllib.request.urlopen",
    "urllib.urlopen",
    "http.client.HTTPConnection",
    "http.client.HTTPSConnection",
})


def is_install_hook_scope(filepath: str) -> bool:
    """Returns True if this file is install-hook (HIGH) scope."""
    name = os.path.basename(filepath)
    return name in _INSTALL_HOOK_NAMES or name.endswith(".pth")


def scan_pth_file(filepath: str) -> List[Finding]:
    """
    Scan a .pth file for executable content.

    .pth files must only contain directory paths (one per line).
    Any parseable Python code is a supply chain attack vector (CRITICAL).

    The litellm 1.82.8 attack used exactly this technique:
    a .pth file containing `import os; os.system(...)` to exfiltrate credentials.
    """
    findings = []
    try:
        with open(filepath, "r", encoding="utf-8", errors="replace") as f:
            for lineno, raw_line in enumerate(f, 1):
                line = raw_line.strip()
                if not line or line.startswith("#"):
                    continue
                # .pth files should only contain directory paths or import statements
                # that add paths. Any Python code is a red flag.
                has_code_chars = any(c in line for c in ("(", ";", "="))
                has_code_keywords = any(
                    kw in line
                    for kw in ("import ", "exec(", "eval(", "__import__")
                )
                if has_code_chars or has_code_keywords:
                    findings.append(Finding(
                        level=RiskLevel.CRITICAL,
                        file_path=filepath,
                        line=lineno,
                        description=f".pth file contains executable Python code",
                        snippet=line[:100],
                    ))
                    continue
                # Secondary check: try to parse as Python — if it parses, it's code
                try:
                    compiled = ast.parse(line, mode="exec")
                    # Valid Python that is not just a plain path string
                    if not (
                        len(compiled.body) == 1
                        and isinstance(compiled.body[0], ast.Expr)
                        and isinstance(compiled.body[0].value, ast.Constant)
                        and isinstance(compiled.body[0].value.value, str)
                    ):
                        findings.append(Finding(
                            level=RiskLevel.CRITICAL,
                            file_path=filepath,
                            line=lineno,
                            description=f".pth file contains parseable Python code",
                            snippet=line[:100],
                        ))
                except SyntaxError:
                    pass  # Not valid Python, assume it's a path
    except OSError:
        pass
    return findings


def scan_python_file(filepath: str, is_hook: bool = False) -> List[Finding]:
    """
    Scan a Python source file using AST analysis.

    is_hook=True applies the install-hook severity tier (CRITICAL/HIGH).
    is_hook=False applies the runtime severity tier (MEDIUM/LOW).
    """
    findings: List[Finding] = []

    try:
        if os.path.getsize(filepath) > 1_048_576:  # 1 MB limit
            return findings
        with open(filepath, "r", encoding="utf-8", errors="replace") as f:
            source = f.read()
    except OSError:
        return findings

    # Text-level check: eval/exec on base64-decoded content (obfuscated payload)
    if re.search(r"b64decode\s*\(", source):
        if re.search(r"(?:exec|eval)\s*\(.*b64decode", source, re.DOTALL):
            findings.append(Finding(
                level=RiskLevel.CRITICAL,
                file_path=filepath,
                line=0,
                description="exec/eval on base64-decoded content — obfuscated payload pattern",
            ))

    try:
        tree = ast.parse(source, filename=filepath)
    except SyntaxError:
        # Cannot parse — return what we found at text level
        return findings

    for node in ast.walk(tree):
        lineno = getattr(node, "lineno", 0)

        # ── Credential path access ──────────────────────────────────────────────
        if isinstance(node, ast.Constant) and isinstance(node.value, str):
            for cred in CREDENTIAL_PATHS:
                if cred in node.value:
                    level = RiskLevel.HIGH if is_hook else RiskLevel.MEDIUM
                    findings.append(Finding(
                        level=level,
                        file_path=filepath,
                        line=lineno,
                        description=f"Access to credential path: {cred}",
                        snippet=node.value[:100],
                    ))
                    break

        # ── Dynamic code execution in install hooks ─────────────────────────────
        if is_hook and isinstance(node, ast.Call):
            name = _call_name(node)
            if name in ("exec", "eval", "compile"):
                findings.append(Finding(
                    level=RiskLevel.CRITICAL,
                    file_path=filepath,
                    line=lineno,
                    description=f"Dynamic code execution ({name}()) in install hook",
                ))

        # ── os.system / os.popen in install hooks (always shell execution) ────────
        if is_hook and isinstance(node, ast.Call):
            name = _call_name(node)
            if name in ("os.system", "os.popen"):
                findings.append(Finding(
                    level=RiskLevel.HIGH,
                    file_path=filepath,
                    line=lineno,
                    description=f"Shell execution ({name}()) in install hook",
                ))

        # ── subprocess shell=True in install hooks ──────────────────────────────
        if is_hook and isinstance(node, ast.Call):
            name = _call_name(node)
            if name in (
                "subprocess.run", "subprocess.call", "subprocess.check_call",
                "subprocess.check_output", "subprocess.Popen",
            ):
                for kw in getattr(node, "keywords", []):
                    if kw.arg == "shell" and isinstance(kw.value, ast.Constant):
                        if kw.value.value is True:
                            findings.append(Finding(
                                level=RiskLevel.HIGH,
                                file_path=filepath,
                                line=lineno,
                                description=f"subprocess with shell=True in install hook",
                            ))

        # ── Network calls ────────────────────────────────────────────────────────
        if isinstance(node, ast.Call):
            name = _call_name(node)
            if name in _NETWORK_FUNCS:
                level = RiskLevel.CRITICAL if is_hook else RiskLevel.MEDIUM
                label = "install hook" if is_hook else "runtime code"
                findings.append(Finding(
                    level=level,
                    file_path=filepath,
                    line=lineno,
                    description=f"Outbound network call ({name}()) in {label}",
                ))

        # ── Sensitive env var access ─────────────────────────────────────────────
        if isinstance(node, ast.Call):
            name = _call_name(node)
            if name in ("os.environ.get", "os.getenv") and node.args:
                arg0 = node.args[0]
                if isinstance(arg0, ast.Constant) and isinstance(arg0.value, str):
                    if _SENSITIVE_ENV_RE.search(arg0.value):
                        findings.append(Finding(
                            level=RiskLevel.MEDIUM,
                            file_path=filepath,
                            line=lineno,
                            description=f"Access to sensitive env var: {arg0.value!r}",
                        ))

        # ── Dynamic imports (LOW) ────────────────────────────────────────────────
        if isinstance(node, ast.Call):
            name = _call_name(node)
            if name in ("importlib.import_module", "__import__"):
                findings.append(Finding(
                    level=RiskLevel.LOW,
                    file_path=filepath,
                    line=lineno,
                    description=f"Dynamic import: {name}()",
                ))

    return findings


def scan_binary_extensions(
    binary_files: List[str],
    has_python_source: bool,
) -> List[Finding]:
    """
    Generate findings for compiled binary extension files (.so, .pyd, .dylib).

    When the package has Python source alongside binary extensions, each
    extension file generates a LOW finding — the AST scanner is blind to any
    payload embedded in compiled code (TODO-1).

    When the package has NO Python source at all (binary-only), a single MEDIUM
    finding is emitted because pipguard's core scan promise cannot be fulfilled.
    """
    if not binary_files:
        return []

    if not has_python_source:
        # Binary-only: one MEDIUM finding summarising the whole package.
        return [Finding(
            level=RiskLevel.MEDIUM,
            file_path=binary_files[0],
            line=0,
            description=(
                "binary-only wheel — no Python source to scan; "
                "cannot verify package contents"
            ),
        )]

    # Mixed: Python source present, but compiled extensions also exist.
    findings = []
    for filepath in binary_files:
        findings.append(Finding(
            level=RiskLevel.LOW,
            file_path=filepath,
            line=0,
            description=(
                "compiled binary extension — cannot inspect for malicious code"
            ),
        ))
    return findings


def _call_name(node: ast.Call) -> str:
    """Extract a dotted name from a Call node's func attribute."""
    if isinstance(node.func, ast.Name):
        return node.func.id
    if isinstance(node.func, ast.Attribute):
        parts = []
        curr = node.func
        while isinstance(curr, ast.Attribute):
            parts.append(curr.attr)
            curr = curr.value
        if isinstance(curr, ast.Name):
            parts.append(curr.id)
        return ".".join(reversed(parts))
    return ""
