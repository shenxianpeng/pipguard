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
from typing import Dict, List, Optional

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

# Path segments that reconstruct a credential path when assembled via
# os.path.join(...), even though no single string literal matches
# CREDENTIAL_PATHS. Kept intentionally specific to avoid false positives.
_CREDENTIAL_PATH_COMPONENTS = frozenset({
    ".ssh",
    ".aws",
    ".kube",
    ".gnupg",
    ".netrc",
    ".git-credentials",
    "id_rsa",
    "id_ed25519",
    "id_ecdsa",
})

# Path-join callables whose assembled segments we inspect for credential paths.
_PATH_JOIN_FUNCS = frozenset({
    "os.path.join",
    "posixpath.join",
    "ntpath.join",
})

# Dynamic-import callables whose string argument names the imported module.
_DYNAMIC_IMPORT_FUNCS = frozenset({
    "__import__",
    "importlib.import_module",
})

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
    "urllib.request.urlretrieve",
    "urllib.urlopen",
    "urllib.urlretrieve",
    "http.client.HTTPConnection",
    "http.client.HTTPSConnection",
})

# Shell / process-execution calls — always CRITICAL in install-hook scope.
# Covers the exec* family (process replacement), spawn*, posix equivalents,
# and pty.spawn, in addition to os.system / os.popen.
_SHELL_EXEC_FUNCS = frozenset({
    "os.system",
    "os.popen",
    "posix.system",
    "posix.popen",
    "os.execv", "os.execve", "os.execvp", "os.execvpe",
    "os.execl", "os.execle", "os.execlp", "os.execlpe",
    "os.spawnv", "os.spawnve", "os.spawnvp", "os.spawnvpe",
    "os.spawnl", "os.spawnle", "os.spawnlp", "os.spawnlpe",
    "posix.execv", "posix.execve",
    "pty.spawn",
})

# runpy executes arbitrary Python from a path/module — code execution.
_RUNPY_EXEC_FUNCS = frozenset({
    "runpy.run_path",
    "runpy.run_module",
})

_BINARY_SCAN_LIMIT = 2 * 1024 * 1024  # 2MB quick heuristic scan
_BINARY_IOCS = (
    (b"/.ssh/id_rsa", RiskLevel.HIGH, "binary contains SSH private-key path indicator"),
    (b"/.aws/credentials", RiskLevel.HIGH, "binary contains AWS credentials-path indicator"),
    (b"/.kube/config", RiskLevel.HIGH, "binary contains kubeconfig-path indicator"),
    (b"aws_secret_access_key", RiskLevel.HIGH, "binary references AWS secret key token"),
    (b"socket", RiskLevel.MEDIUM, "binary contains network API indicator"),
    (b"http://", RiskLevel.MEDIUM, "binary contains cleartext HTTP indicator"),
    (b"https://", RiskLevel.MEDIUM, "binary contains HTTPS indicator"),
    (b"/bin/sh", RiskLevel.MEDIUM, "binary contains shell execution indicator"),
)

# ctypes functions that load native code — any use in install hooks is dangerous
_CTYPES_DANGEROUS = frozenset({
    "ctypes.CDLL",
    "ctypes.WinDLL",
    "ctypes.OleDLL",
    "ctypes.pydll",
    "ctypes.windll",
    "ctypes.cdll",
    "ctypes.oledll",
    "ctypes.pythonapi.PyRun_SimpleString",
})

# Pickle deserialization — arbitrary code execution
_PICKLE_DESERIALIZE = frozenset({
    "pickle.loads",
    "pickle.load",
    "_pickle.loads",
    "_pickle.load",
    "cPickle.loads",
    "cPickle.load",
    "dill.loads",
    "dill.load",
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
        file_size = os.path.getsize(filepath)
        with open(filepath, "r", encoding="utf-8", errors="replace") as f:
            source = f.read()
    except OSError:
        return findings

    if file_size > 1_048_576:
        findings.append(Finding(
            level=RiskLevel.HIGH if is_hook else RiskLevel.MEDIUM,
            file_path=filepath,
            line=0,
            description=(
                "large source file (>1MB) — scan confidence reduced; "
                "review package manually"
            ),
        ))

    try:
        tree = ast.parse(source, filename=filepath)
    except SyntaxError:
        # Text-level fallback for malformed files where AST parsing fails.
        # Keep this intentionally strict to avoid false positives from
        # unrelated exec/eval and b64decode usage in the same file.
        if re.search(r"(?:exec|eval)\s*\(\s*(?:base64\.)?b64decode\s*\(", source):
            findings.append(Finding(
                level=RiskLevel.CRITICAL,
                file_path=filepath,
                line=0,
                description=(
                    "exec/eval on base64-decoded content — "
                    "obfuscated payload pattern"
                ),
            ))
        return findings

    aliases = _build_alias_map(tree)

    for node in ast.walk(tree):
        lineno = getattr(node, "lineno", 0)

        # ── Obfuscated payload pattern: exec/eval(base64.b64decode(...)) ───────
        if isinstance(node, ast.Call):
            name = _resolved_call_name(node, aliases)
            if name in ("exec", "eval"):
                for arg in node.args:
                    for sub in ast.walk(arg):
                        if isinstance(sub, ast.Call):
                            sub_name = _resolved_call_name(sub, aliases)
                            if sub_name and sub_name.endswith("b64decode"):
                                findings.append(Finding(
                                    level=RiskLevel.CRITICAL,
                                    file_path=filepath,
                                    line=lineno,
                                    description=(
                                        "exec/eval on base64-decoded content — "
                                        "obfuscated payload pattern"
                                    ),
                                ))
                                break
                    else:
                        continue
                    break

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

        # ── Credential path constructed via os.path.join(...) ───────────────────
        if isinstance(node, ast.Call):
            name = _resolved_call_name(node, aliases)
            if name in _PATH_JOIN_FUNCS:
                component = _credential_join_component(node)
                if component:
                    level = RiskLevel.HIGH if is_hook else RiskLevel.MEDIUM
                    findings.append(Finding(
                        level=level,
                        file_path=filepath,
                        line=lineno,
                        description=(
                            "Credential path constructed via os.path.join: "
                            f"{component}"
                        ),
                        snippet=component,
                    ))

        # ── Dynamic code execution in install hooks ─────────────────────────────
        if is_hook and isinstance(node, ast.Call):
            name = _resolved_call_name(node, aliases)
            if name in ("exec", "eval", "compile") or name in _RUNPY_EXEC_FUNCS:
                findings.append(Finding(
                    level=RiskLevel.CRITICAL,
                    file_path=filepath,
                    line=lineno,
                    description=f"Dynamic code execution ({name}()) in install hook",
                ))

        # ── ctypes native code loading in install hooks ───────────────────────
        if is_hook and isinstance(node, ast.Call):
            name = _resolved_call_name(node, aliases)
            if name in _CTYPES_DANGEROUS or any(
                name.startswith(prefix + ".") for prefix in _CTYPES_DANGEROUS
            ):
                findings.append(Finding(
                    level=RiskLevel.CRITICAL,
                    file_path=filepath,
                    line=lineno,
                    description=f"ctypes native code loading ({name}()) in install hook",
                ))

        # ── Pickle deserialization in install hooks ───────────────────────────
        if is_hook and isinstance(node, ast.Call):
            name = _resolved_call_name(node, aliases)
            if name in _PICKLE_DESERIALIZE:
                findings.append(Finding(
                    level=RiskLevel.HIGH,
                    file_path=filepath,
                    line=lineno,
                    description=f"Unsafe deserialization ({name}()) in install hook — arbitrary code execution risk",
                ))

        # ── marshal.loads + exec/compile chain in any code ─────────────────────
        if isinstance(node, ast.Call):
            name = _resolved_call_name(node, aliases)
            if name in ("exec", "eval"):
                for arg in node.args:
                    for sub in ast.walk(arg):
                        if isinstance(sub, ast.Call):
                            sub_name = _resolved_call_name(sub, aliases)
                            if sub_name and sub_name.endswith("loads") and "marshal" in sub_name:
                                findings.append(Finding(
                                    level=RiskLevel.CRITICAL,
                                    file_path=filepath,
                                    line=lineno,
                                    description=(
                                        "exec/eval on marshal-deserialized object — "
                                        "obfuscated code-object payload"
                                    ),
                                ))
                                break
                            if sub_name and "compile" in sub_name:
                                findings.append(Finding(
                                    level=RiskLevel.CRITICAL,
                                    file_path=filepath,
                                    line=lineno,
                                    description=(
                                        "exec/eval on compile() output — "
                                        "multi-stage obfuscated execution"
                                    ),
                                ))
                                break
                    else:
                        continue
                    break

        # ── Wildcard import in install hooks ──────────────────────────────────
        if is_hook and isinstance(node, (ast.ImportFrom,)):
            for spec in getattr(node, "names", []):
                if isinstance(spec, ast.alias) and spec.name == "*":
                    findings.append(Finding(
                        level=RiskLevel.MEDIUM,
                        file_path=filepath,
                        line=lineno,
                        description=(
                            f"Wildcard import (from {node.module or '?'} import *) "
                            "in install hook — blinds the scanner"
                        ),
                    ))
                    break

        # ── tempfile + dangerous usage in install hooks ──────────────────────
        if is_hook and isinstance(node, ast.Call):
            name = _resolved_call_name(node, aliases)
            # Detect writing content to tempfile + executing it
            if name in ("tempfile.mkstemp", "tempfile.mkdtemp", "tempfile.NamedTemporaryFile",
                        "tempfile.TemporaryFile"):
                findings.append(Finding(
                    level=RiskLevel.MEDIUM,
                    file_path=filepath,
                    line=lineno,
                    description=f"tempfile usage ({name}()) in install hook — potential write-and-execute",
                ))

        # ── shell / process execution in install hooks (os.system, exec*, …) ──────
        if is_hook and isinstance(node, ast.Call):
            name = _resolved_call_name(node, aliases)
            if name in _SHELL_EXEC_FUNCS:
                findings.append(Finding(
                    level=RiskLevel.CRITICAL,
                    file_path=filepath,
                    line=lineno,
                    description=f"Shell execution ({name}()) in install hook",
                ))

        # ── subprocess execution in install hooks ──────────────────────────────
        if is_hook and isinstance(node, ast.Call):
            name = _resolved_call_name(node, aliases)
            if name in (
                "subprocess.run", "subprocess.call", "subprocess.check_call",
                "subprocess.check_output", "subprocess.Popen",
            ):
                if _subprocess_invokes_shell(node):
                    findings.append(Finding(
                        level=RiskLevel.CRITICAL,
                        file_path=filepath,
                        line=lineno,
                        description="subprocess shell execution in install hook",
                    ))
                else:
                    findings.append(Finding(
                        level=RiskLevel.HIGH,
                        file_path=filepath,
                        line=lineno,
                        description=f"subprocess execution ({name}()) in install hook",
                    ))

        # ── Network calls ────────────────────────────────────────────────────────
        if isinstance(node, ast.Call):
            name = _resolved_call_name(node, aliases)
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
            name = _resolved_call_name(node, aliases)
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
            name = _resolved_call_name(node, aliases)
            if name in ("importlib.import_module", "__import__"):
                findings.append(Finding(
                    level=RiskLevel.LOW,
                    file_path=filepath,
                    line=lineno,
                    description=f"Dynamic import: {name}()",
                ))

        # ── ctypes usage in runtime code ────────────────────────────────────────
        if not is_hook and isinstance(node, ast.Call):
            name = _resolved_call_name(node, aliases)
            if name in _CTYPES_DANGEROUS or any(
                name.startswith(prefix + ".") for prefix in _CTYPES_DANGEROUS
            ):
                findings.append(Finding(
                    level=RiskLevel.HIGH,
                    file_path=filepath,
                    line=lineno,
                    description=f"ctypes native code loading ({name}()) in runtime code",
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
        findings = [Finding(
            level=RiskLevel.MEDIUM,
            file_path=binary_files[0],
            line=0,
            description=(
                "binary-only wheel — no Python source to scan; "
                "cannot verify package contents"
            ),
        )]
        for filepath in binary_files:
            findings.extend(_scan_binary_file_for_iocs(filepath))
        return findings

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
        findings.extend(_scan_binary_file_for_iocs(filepath))
    return findings


def _scan_binary_file_for_iocs(filepath: str) -> List[Finding]:
    """Best-effort binary IOC scan using printable/string signatures."""
    findings: List[Finding] = []
    try:
        with open(filepath, "rb") as f:
            blob = f.read(_BINARY_SCAN_LIMIT).lower()
    except OSError:
        return findings

    for marker, level, description in _BINARY_IOCS:
        if marker in blob:
            findings.append(Finding(
                level=level,
                file_path=filepath,
                line=0,
                description=description,
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


def _build_alias_map(tree: ast.AST) -> Dict[str, str]:
    """Build a simple alias map for imports and one-hop assignments."""
    aliases: Dict[str, str] = {}

    for node in ast.walk(tree):
        if isinstance(node, ast.Import):
            for spec in node.names:
                if spec.asname:
                    # `import a.b.c as x` binds `x` -> the a.b.c module
                    aliases[spec.asname] = spec.name
                else:
                    # `import a.b.c` binds the top package `a`, which refers to
                    # module `a` — NOT a.b.c. Mapping it to the full dotted name
                    # would double-count segments (e.g. urllib.request.urlopen
                    # resolving to urllib.request.request.urlopen).
                    top = spec.name.split(".")[0]
                    aliases[top] = top

        elif isinstance(node, ast.ImportFrom):
            if not node.module:
                continue
            for spec in node.names:
                if spec.name == "*":
                    continue
                local = spec.asname or spec.name
                aliases[local] = f"{node.module}.{spec.name}"

        elif isinstance(node, ast.Assign):
            resolved = _resolve_expr_name(node.value, aliases)
            if resolved is None and isinstance(node.value, ast.Constant) and isinstance(node.value.value, str):
                # Track a one-hop string constant so reflection through a
                # variable resolves, e.g. `s = "system"; getattr(os, s)()`.
                resolved = node.value.value
            if not resolved:
                continue
            for target in node.targets:
                if isinstance(target, ast.Name):
                    aliases[target.id] = resolved

    return aliases


def _resolved_call_name(node: ast.Call, aliases: Dict[str, str]) -> str:
    return _resolve_expr_name(node.func, aliases) or _call_name(node)


def _resolve_expr_name(expr: ast.AST, aliases: Dict[str, str]) -> Optional[str]:
    """Resolve a best-effort dotted name from Name/Attribute/getattr(...)."""
    if isinstance(expr, ast.Name):
        return aliases.get(expr.id, expr.id)

    if isinstance(expr, ast.Attribute):
        base = _resolve_expr_name(expr.value, aliases)
        if not base:
            return None
        return f"{base}.{expr.attr}"

    if isinstance(expr, ast.Call):
        callee = _resolve_expr_name(expr.func, aliases)
        # getattr(module_or_alias, "attr") -> module.attr
        # attr may be a string literal or a variable holding a string constant.
        if callee == "getattr" and len(expr.args) >= 2:
            base = _resolve_expr_name(expr.args[0], aliases)
            attr = expr.args[1]
            attr_name = None
            if isinstance(attr, ast.Constant) and isinstance(attr.value, str):
                attr_name = attr.value
            elif isinstance(attr, ast.Name):
                candidate = aliases.get(attr.id)
                if isinstance(candidate, str) and candidate and "." not in candidate:
                    attr_name = candidate
            if base and attr_name:
                return f"{base}.{attr_name}"
        # __import__("os") / importlib.import_module("os") -> os
        # so chained calls like __import__("os").system(...) resolve to os.system
        if callee in _DYNAMIC_IMPORT_FUNCS and expr.args:
            mod = expr.args[0]
            if isinstance(mod, ast.Constant) and isinstance(mod.value, str):
                return mod.value

    return None


def _credential_join_component(node: ast.Call) -> Optional[str]:
    """Return the first sensitive segment in an os.path.join(...) call, if any.

    Catches credential paths assembled from separate literals — e.g.
    ``os.path.join(os.path.expanduser("~"), ".ssh", "id_rsa")`` — which evade
    the literal-substring match against CREDENTIAL_PATHS.
    """
    for arg in node.args:
        if isinstance(arg, ast.Constant) and isinstance(arg.value, str):
            segment = arg.value.strip().strip("/")
            if segment in _CREDENTIAL_PATH_COMPONENTS:
                return segment
    return None


def _subprocess_invokes_shell(node: ast.Call) -> bool:
    """Return True for subprocess calls that execute via shell semantics."""
    for kw in getattr(node, "keywords", []):
        if kw.arg == "shell" and isinstance(kw.value, ast.Constant) and kw.value.value is True:
            return True

    if not node.args:
        return False
    cmd = node.args[0]
    if isinstance(cmd, ast.List) and len(cmd.elts) >= 2:
        first = cmd.elts[0]
        second = cmd.elts[1]
        if (
            isinstance(first, ast.Constant) and isinstance(first.value, str)
            and isinstance(second, ast.Constant) and isinstance(second.value, str)
            and first.value in ("sh", "bash", "zsh", "cmd", "powershell", "pwsh")
            and second.value in ("-c", "/c", "-Command")
        ):
            return True
    return False
