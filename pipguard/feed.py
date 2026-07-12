"""PyPI RSS feed support for the reporter workflow (Issues #40, #41).

pipguard's most realistic differentiator is not scanning the whole ecosystem, but
assisting a human reporter: watch the PyPI new-package / new-release feed, scan
each entry, and surface the few high-risk ones worth a manual look (and, if
confirmed malicious, an advisory PR).

This module fetches and parses the feed. Pure stdlib (urllib + ElementTree), no
third-party dependencies.
"""

from __future__ import annotations

import re
import urllib.request
import xml.etree.ElementTree as ET
from dataclasses import dataclass
from pathlib import Path
from typing import List, Optional

# Named shortcuts for the two PyPI RSS feeds.
FEED_URLS = {
    "updates": "https://pypi.org/rss/updates.xml",   # new releases of existing packages
    "packages": "https://pypi.org/rss/packages.xml",  # brand-new packages
}

_FETCH_TIMEOUT = 10  # seconds

# https://pypi.org/project/<name>/<version>/  →  capture name and (optional) version
_PROJECT_LINK_RE = re.compile(
    r"/project/(?P<name>[^/]+)/(?:(?P<version>[^/]+)/?)?$"
)
# A loose version token: starts with a digit (e.g. 1.2.3, 2024.1, 1.0rc1).
_VERSION_TOKEN_RE = re.compile(r"^\d[\w.\-+!]*$")


@dataclass
class FeedEntry:
    """A single item from a PyPI RSS feed."""

    name: str
    version: str = ""
    title: str = ""
    link: str = ""
    published: str = ""

    def to_spec(self) -> str:
        """Return a pip requirement spec: ``name==version`` or just ``name``."""
        return f"{self.name}=={self.version}" if self.version else self.name


def fetch_feed(source: str, timeout: float = _FETCH_TIMEOUT) -> str:
    """Fetch raw feed XML from a named shortcut, URL, or local file.

    Best-effort: returns "" on any network / IO error.
    """
    if not source:
        return ""
    resolved = FEED_URLS.get(source, source)

    if resolved.startswith(("http://", "https://")):
        try:
            with urllib.request.urlopen(resolved, timeout=timeout) as resp:
                return resp.read().decode("utf-8", errors="replace")
        except Exception:
            return ""

    p = Path(resolved)
    if not p.exists():
        return ""
    try:
        return p.read_text(encoding="utf-8")
    except OSError:
        return ""


def _name_version_from_link(link: str) -> Optional[tuple]:
    m = _PROJECT_LINK_RE.search(link.strip())
    if not m:
        return None
    name = m.group("name")
    version = m.group("version") or ""
    return name, version


def _name_version_from_title(title: str) -> tuple:
    parts = title.split()
    if len(parts) >= 2 and _VERSION_TOKEN_RE.match(parts[-1]):
        return parts[0], parts[-1]
    if parts:
        return parts[0], ""
    return "", ""


def parse_feed(xml_text: str) -> List[FeedEntry]:
    """Parse PyPI RSS XML into FeedEntry records.

    Prefers name/version from the item ``<link>`` (``/project/<name>/<version>/``)
    and falls back to the ``<title>``. Malformed XML yields an empty list.
    """
    if not xml_text:
        return []
    try:
        root = ET.fromstring(xml_text)
    except ET.ParseError:
        return []

    entries: List[FeedEntry] = []
    for item in root.iter("item"):
        title = (item.findtext("title") or "").strip()
        link = (item.findtext("link") or "").strip()
        published = (item.findtext("pubDate") or "").strip()

        name = version = ""
        from_link = _name_version_from_link(link)
        if from_link:
            name, version = from_link
        if not name:
            name, version = _name_version_from_title(title)
        if not version:
            # title may still carry a version even when the link is a project root
            _, tv = _name_version_from_title(title)
            version = version or tv

        if not name:
            continue
        entries.append(FeedEntry(
            name=name,
            version=version,
            title=title,
            link=link,
            published=published,
        ))
    return entries
