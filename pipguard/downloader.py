"""Download packages using pip without executing any package code.

Architecture Amendment A1: Use --prefer-binary, detect sdist fallback by extension.
Architecture Amendment A10: Check disk space before download.
"""

import os
import shutil
import subprocess
import sys
from pathlib import Path
from typing import List, Tuple

SDIST_EXTENSIONS = (".tar.gz", ".tar.bz2", ".tgz", ".zip")
MINIMUM_DISK_MB = 500


def check_disk_space(path: str) -> None:
    """Warn (not error) if available disk space is below threshold."""
    try:
        stat = shutil.disk_usage(path)
        free_mb = stat.free // (1024 * 1024)
        if free_mb < MINIMUM_DISK_MB:
            print(
                f"WARNING: Low disk space — {free_mb}MB free "
                f"(recommended: {MINIMUM_DISK_MB}MB+)",
                file=sys.stderr,
            )
    except OSError:
        pass


def download_packages(
    packages: List[str],
    dest_dir: str,
    allow_sdist: bool = False,
    requirements_file: str = None,
    require_hashes: bool = False,
) -> Tuple[List[str], List[str]]:
    """
    Download packages to dest_dir using pip download --prefer-binary.

    Returns (archive_files, sdist_reject_names).

    sdist_reject_names is non-empty when --prefer-binary fell back to an sdist
    and --allow-sdist was not set. Callers should exit 2 in that case.

    Detection is file-extension-based (not flag-based) so that silent fallbacks
    are always caught (Architecture Amendment A1).
    """
    check_disk_space(dest_dir)

    cmd = [
        sys.executable, "-m", "pip", "download",
        "--prefer-binary",
        "--dest", dest_dir,
        "--quiet",
    ]
    if requirements_file:
        cmd += ["-r", requirements_file]
    else:
        cmd += packages
    if require_hashes:
        cmd += ["--require-hashes"]

    result = subprocess.run(cmd, capture_output=True, text=True)
    if result.returncode != 0:
        raise RuntimeError(f"pip download failed:\n{result.stderr.strip()}")

    downloaded = list(Path(dest_dir).iterdir())
    archive_files: List[str] = []
    sdist_rejects: List[str] = []

    for f in downloaded:
        fname = f.name
        if fname.endswith(".whl"):
            archive_files.append(str(f))
        elif any(fname.endswith(ext) for ext in SDIST_EXTENSIONS):
            if allow_sdist:
                print(
                    f"WARNING: sdist package {fname} — pip will execute code during "
                    f"metadata extraction. Proceeding because --allow-sdist was set.",
                    file=sys.stderr,
                )
                archive_files.append(str(f))
            else:
                sdist_rejects.append(fname)

    return archive_files, sdist_rejects
