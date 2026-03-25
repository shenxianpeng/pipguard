"""Extract wheel and sdist archives into a temp directory for scanning."""

import os
import tarfile
import zipfile
from typing import Generator, Optional, Tuple


def extract_archive(archive_path: str, dest_dir: str) -> Optional[str]:
    """
    Extract a wheel (.whl) or sdist (.tar.gz/.zip) to dest_dir.

    Returns the extraction subdirectory path, or None on failure.
    Wheels are zip archives; sdists are tar.gz or tar.bz2.
    """
    fname = os.path.basename(archive_path)
    extract_to = os.path.join(dest_dir, fname + "_extracted")
    os.makedirs(extract_to, exist_ok=True)

    if archive_path.endswith(".whl") or (
        archive_path.endswith(".zip") and not _is_sdist_zip(archive_path)
    ):
        try:
            with zipfile.ZipFile(archive_path, "r") as zf:
                zf.extractall(extract_to)
            return extract_to
        except (zipfile.BadZipFile, OSError):
            return None

    if (
        archive_path.endswith(".tar.gz")
        or archive_path.endswith(".tgz")
        or archive_path.endswith(".tar.bz2")
        or archive_path.endswith(".zip")
    ):
        try:
            mode = "r:*" if not archive_path.endswith(".zip") else "r"
            if archive_path.endswith(".zip"):
                with zipfile.ZipFile(archive_path, "r") as zf:
                    zf.extractall(extract_to)
            else:
                with tarfile.open(archive_path, mode) as tf:
                    tf.extractall(extract_to)
            return extract_to
        except (tarfile.TarError, zipfile.BadZipFile, EOFError, OSError):
            return None

    return None


def _is_sdist_zip(path: str) -> bool:
    """Heuristic: zip with setup.py or pyproject.toml at top level = sdist."""
    try:
        with zipfile.ZipFile(path, "r") as zf:
            names = zf.namelist()
            return any(
                n.endswith("/setup.py") or n.endswith("/pyproject.toml")
                for n in names
            )
    except (zipfile.BadZipFile, OSError):
        return False


def collect_scannable_files(
    extract_dir: str,
) -> Generator[Tuple[str, bool], None, None]:
    """
    Walk an extracted package directory, yielding (filepath, is_hook_scope).

    is_hook_scope=True for: setup.py, setup.cfg, pyproject.toml, *.pth
    is_hook_scope=False for all other .py files.

    Skips __pycache__, .git, and test directories (not executed during install).
    """
    hook_names = frozenset({"setup.py", "setup.cfg", "pyproject.toml"})
    skip_dirs = frozenset({"__pycache__", ".git", "tests", "test", ".tox"})

    for root, dirs, files in os.walk(extract_dir):
        dirs[:] = [d for d in dirs if d not in skip_dirs]
        for fname in files:
            filepath = os.path.join(root, fname)
            is_hook = fname in hook_names or fname.endswith(".pth")
            if fname.endswith(".py") or fname in hook_names or fname.endswith(".pth"):
                yield filepath, is_hook


def has_python_source(extract_dir: str) -> bool:
    """Returns True if the extracted package contains any .py source files."""
    for root, dirs, files in os.walk(extract_dir):
        dirs[:] = [d for d in dirs if d != "__pycache__"]
        for fname in files:
            if fname.endswith(".py"):
                return True
    return False
