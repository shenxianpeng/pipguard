"""Experimental capability sandbox for the install step (spike for #55).

**Status: experimental prototype — not wired into the default install gate.**
See ``docs/runtime-sandbox.md`` for the design and trade-offs.

pipguard's threat model is malicious *Python* code that runs during
installation (``setup.py`` / ``pyproject.toml`` build backends / ``.pth``
autorun). Python's audit hooks (PEP 578) are a natural, portable enforcement
point for exactly that: a hook installed via a generated ``sitecustomize`` on
``PYTHONPATH`` fires in every Python subprocess and can veto a capability —
reading a credential path, opening an outbound connection, or spawning a
process — by raising before the underlying syscall happens.

This is deliberately Python-only. It does **not** contain payloads in compiled
extensions (``.so``) or non-Python child processes; OS-level sandboxing
(landlock / seccomp / bubblewrap) is the complementary hardening layer
discussed in the design note.
"""

from __future__ import annotations

import os
import shutil
import subprocess
import tempfile
from pathlib import Path
from typing import List, Optional, Sequence

# Path fragments that, once a path is normalised, indicate a credential store.
# Matched as substrings of the absolute, user-expanded path.
DEFAULT_DENY_FRAGMENTS: List[str] = [
    "/.ssh/",
    "/.aws/",
    "/.kube/",
    "/.gnupg/",
    "/.config/gcloud/",
    "/.netrc",
    "/.git-credentials",
]


def path_is_denied(path: str, deny_fragments: Sequence[str]) -> bool:
    """Return True if ``path`` resolves into a denied credential location.

    Normalises with ``expanduser`` + ``abspath`` first so that ``~/.ssh/id_rsa``
    and relative paths are caught, then checks for any denied fragment.
    """
    if not path:
        return False
    try:
        resolved = os.path.abspath(os.path.expanduser(str(path)))
    except (ValueError, TypeError):
        return False
    return any(frag in resolved for frag in deny_fragments)


def make_sitecustomize(
    deny_fragments: Sequence[str],
    allow_network: bool,
    allow_subprocess: bool,
) -> str:
    """Return self-contained ``sitecustomize.py`` source installing the hook.

    Self-contained (no pipguard import) so it works in any subprocess regardless
    of whether pipguard is importable there.
    """
    return (
        "import os, sys\n"
        f"_DENY = {list(deny_fragments)!r}\n"
        f"_ALLOW_NET = {bool(allow_network)!r}\n"
        f"_ALLOW_SUB = {bool(allow_subprocess)!r}\n"
        "def _denied(path):\n"
        "    if not path:\n"
        "        return False\n"
        "    try:\n"
        "        p = os.path.abspath(os.path.expanduser(str(path)))\n"
        "    except Exception:\n"
        "        return False\n"
        "    return any(f in p for f in _DENY)\n"
        "def _hook(event, args):\n"
        "    if event == 'open' and args and _denied(args[0]):\n"
        "        raise PermissionError('pipguard-sandbox: blocked access to ' + str(args[0]))\n"
        "    elif event == 'socket.connect' and not _ALLOW_NET:\n"
        "        raise PermissionError('pipguard-sandbox: blocked outbound network connection')\n"
        "    elif event in ('os.system', 'subprocess.Popen') and not _ALLOW_SUB:\n"
        "        raise PermissionError('pipguard-sandbox: blocked process execution')\n"
        "sys.addaudithook(_hook)\n"
    )


def run_sandboxed(
    argv: Sequence[str],
    deny_fragments: Optional[Sequence[str]] = None,
    allow_network: bool = False,
    allow_subprocess: bool = True,
    cwd: Optional[str] = None,
    timeout: Optional[float] = None,
) -> int:
    """Run ``argv`` with the capability audit hook installed in the child.

    The hook is delivered via a generated ``sitecustomize`` prepended to
    ``PYTHONPATH``, so it also applies to any Python subprocess the command
    spawns (e.g. a build backend). Returns the child's exit code; a blocked
    capability makes the child raise and exit non-zero.
    """
    if deny_fragments is None:
        deny_fragments = DEFAULT_DENY_FRAGMENTS

    tmp = tempfile.mkdtemp(prefix="pipguard-sandbox-")
    try:
        (Path(tmp) / "sitecustomize.py").write_text(
            make_sitecustomize(deny_fragments, allow_network, allow_subprocess),
            encoding="utf-8",
        )
        env = os.environ.copy()
        env["PYTHONPATH"] = tmp + os.pathsep + env.get("PYTHONPATH", "")
        proc = subprocess.run(list(argv), env=env, cwd=cwd, timeout=timeout)
        return proc.returncode
    finally:
        shutil.rmtree(tmp, ignore_errors=True)
