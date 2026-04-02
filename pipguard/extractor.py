"""Extract wheel and sdist archives into a temp directory for scanning."""

import os
import sys
import tarfile
import zipfile
from typing import Generator, List, Optional, Tuple

# Compiled binary extension suffixes that cannot be AST-scanned
BINARY_EXTENSIONS = frozenset({".so", ".pyd", ".dylib"})


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
                    if sys.version_info >= (3, 12):
                        tf.extractall(extract_to, filter="data")
                    else:  # pragma: no cover
                        tf.extractall(extract_to, members=_safe_tar_members(tf, extract_to))
            return extract_to
        except (tarfile.TarError, zipfile.BadZipFile, EOFError, OSError):
            return None

    return None


def _safe_tar_members(tf: tarfile.TarFile, dest_dir: str) -> List[tarfile.TarInfo]:  # pragma: no cover
    """Filter tar members to prevent path traversal attacks (Python < 3.12)."""
    real_dest = os.path.realpath(dest_dir)
    safe = []
    for member in tf.getmembers():
        member_path = os.path.realpath(os.path.join(real_dest, member.name))
        if member_path.startswith(real_dest + os.sep) or member_path == real_dest:
            safe.append(member)
    return safe


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


def collect_binary_extension_files(extract_dir: str) -> List[str]:
    """
    Walk an extracted package directory, returning paths to compiled binary
    extension files (.so, .pyd, .dylib).

    These files cannot be AST-scanned and represent a potential attack surface
    that static analysis cannot cover (TODO-1).
    """
    result = []
    skip_dirs = frozenset({"__pycache__", ".git", "tests", "test", ".tox"})
    for root, dirs, files in os.walk(extract_dir):
        dirs[:] = [d for d in dirs if d not in skip_dirs]
        for fname in files:
            _, ext = os.path.splitext(fname)
            if ext in BINARY_EXTENSIONS:
                result.append(os.path.join(root, fname))
    return result
