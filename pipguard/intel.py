"""Threat-intelligence feed support (lightweight JSON denylist)."""

import json
import urllib.request
from pathlib import Path
from typing import Dict, Tuple


def load_intel_feed(source: str) -> Dict[Tuple[str, str], str]:
    """
    Load intel feed from local file or URL.

    Expected JSON format:
    {
      "blocked": [
        {"name": "pkg", "version": "1.2.3", "reason": "malware campaign"}
      ]
    }
    """
    if not source:
        return {}

    raw = _read_source(source)
    if not raw:
        return {}

    try:
        data = json.loads(raw)
    except json.JSONDecodeError:
        return {}

    result: Dict[Tuple[str, str], str] = {}
    for item in data.get("blocked", []):
        name = str(item.get("name", "")).strip().lower()
        version = str(item.get("version", "")).strip()
        reason = str(item.get("reason", "blocked by intel feed")).strip()
        if name and version:
            result[(name, version)] = reason
    return result


def _read_source(source: str) -> str:
    if source.startswith(("http://", "https://")):
        try:
            with urllib.request.urlopen(source, timeout=5) as resp:
                return resp.read().decode("utf-8", errors="replace")
        except Exception:
            return ""

    p = Path(source)
    if not p.exists():
        return ""
    try:
        return p.read_text(encoding="utf-8")
    except OSError:
        return ""
