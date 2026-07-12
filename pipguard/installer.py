"""Install packages from a local directory (TOCTOU-safe).

Architecture Amendment A2: Always use --no-index --find-links, never bare
`pip install <package>` which would re-download from PyPI and defeat the scan.
"""

import subprocess
import sys
from typing import List, Optional

from .sandbox import run_sandboxed


def install_from_local(
    packages: List[str],
    find_links_dir: str,
    requirements_file: Optional[str] = None,
    require_hashes: bool = False,
    show_pip_output: bool = False,
    sandbox: bool = False,
) -> int:
    """
    Install packages using only the already-scanned local files.

    Uses pip install --no-index --find-links so pip CANNOT reach PyPI.
    This closes the TOCTOU race: the files that were scanned are the files
    that get installed — no possibility of substitution.

    With ``sandbox=True`` the pip step runs under the capability sandbox
    (``pipguard.sandbox``): install-time code cannot read credential paths or
    open outbound connections. Network is denied outright — installing from the
    local cache is already offline (``--no-index``) — so this is safe.

    Returns pip's exit code.
    """
    cmd = [
        sys.executable, "-m", "pip", "install",
        "--no-index",
        "--find-links", find_links_dir,
    ]
    if requirements_file:
        cmd += ["-r", requirements_file]
    else:
        cmd += packages
    if require_hashes:
        cmd += ["--require-hashes"]

    if sandbox:
        # Deny credential reads and outbound network; allow subprocesses so
        # legitimate build backends / compilers still work.
        return run_sandboxed(
            cmd,
            allow_network=False,
            allow_subprocess=True,
            capture_output=not show_pip_output,
        )

    if show_pip_output:
        result = subprocess.run(cmd)
        return result.returncode

    result = subprocess.run(cmd, capture_output=True, text=True)
    if result.returncode != 0:
        if result.stdout:
            sys.stdout.write(result.stdout)
        if result.stderr:
            sys.stderr.write(result.stderr)
    return result.returncode
