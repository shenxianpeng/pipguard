
"""
pipguard — Python supply chain security tool.

Scan packages for malicious install-time behavior before installing them.
Zero configuration. Zero external dependencies. Pure stdlib.
"""

from importlib.metadata import version, PackageNotFoundError

try:
    __version__ = version("pipguard")
except PackageNotFoundError:
    __version__ = "0.0.0"  # running from source without installing
