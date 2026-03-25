"""Guaranteed cleanup of temp directories.

Architecture Amendment A9: Register cleanup via both atexit and SIGINT handler
so temp dirs are always removed, even on Ctrl+C or unhandled exceptions.
"""

import atexit
import shutil
import signal
import sys
from typing import List

_registered_dirs: List[str] = []


def register_temp_dir(tmp_dir: str) -> None:
    """Register a temp directory to be deleted on process exit."""
    _registered_dirs.append(tmp_dir)
    atexit.register(shutil.rmtree, tmp_dir, True)  # ignore_errors=True


def install_signal_handlers() -> None:
    """Install SIGINT handler so Ctrl+C cleans up before exiting."""
    def _handler(signum, frame):
        for d in _registered_dirs:
            shutil.rmtree(d, ignore_errors=True)
        print("\nInterrupted. Temp files cleaned up.", file=sys.stderr)
        sys.exit(1)

    signal.signal(signal.SIGINT, _handler)
    signal.signal(signal.SIGTERM, _handler)
