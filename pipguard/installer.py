"""Install packages from a local directory (TOCTOU-safe).

Architecture Amendment A2: Always use --no-index --find-links, never bare
`pip install <package>` which would re-download from PyPI and defeat the scan.
"""

import subprocess
import sys
from typing import List, Optional


def install_from_local(
    packages: List[str],
    find_links_dir: str,
    requirements_file: Optional[str] = None,
    require_hashes: bool = False,
    show_pip_output: bool = False,
) -> int:
    """
    Install packages using only the already-scanned local files.

    Uses pip install --no-index --find-links so pip CANNOT reach PyPI.
    This closes the TOCTOU race: the files that were scanned are the files
    that get installed — no possibility of substitution.

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
