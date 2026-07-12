"""Tests for pipguard.feed — PyPI RSS parsing and fetching (Issues #40/#41)."""

from unittest.mock import MagicMock, patch

from pipguard.feed import FEED_URLS, FeedEntry, fetch_feed, parse_feed

SAMPLE_RSS = """<?xml version="1.0" encoding="UTF-8"?>
<rss version="2.0"><channel>
  <title>PyPI recent updates</title>
  <item>
    <title>evilpkg 1.2.3</title>
    <link>https://pypi.org/project/evilpkg/1.2.3/</link>
    <pubDate>Sun, 12 Jul 2026 10:00:00 GMT</pubDate>
  </item>
  <item>
    <title>foo 2.0rc1</title>
    <link>https://pypi.org/project/foo/2.0rc1/</link>
  </item>
  <item>
    <title>brandnew</title>
    <link>https://pypi.org/project/brandnew/</link>
    <description>added to PyPI</description>
  </item>
</channel></rss>"""


# ── parse_feed ───────────────────────────────────────────────────────────────

def test_parse_extracts_name_version_from_link():
    entries = parse_feed(SAMPLE_RSS)
    assert len(entries) == 3
    assert entries[0].name == "evilpkg"
    assert entries[0].version == "1.2.3"
    assert entries[0].link == "https://pypi.org/project/evilpkg/1.2.3/"
    assert entries[0].published.startswith("Sun,")


def test_parse_prerelease_version():
    entries = parse_feed(SAMPLE_RSS)
    assert entries[1].name == "foo"
    assert entries[1].version == "2.0rc1"


def test_parse_new_package_without_version():
    entries = parse_feed(SAMPLE_RSS)
    assert entries[2].name == "brandnew"
    assert entries[2].version == ""


def test_to_spec():
    assert FeedEntry("foo", "1.0").to_spec() == "foo==1.0"
    assert FeedEntry("foo", "").to_spec() == "foo"


def test_parse_falls_back_to_title_when_link_unhelpful():
    xml = """<rss><channel><item>
      <title>titlepkg 3.4.5</title>
      <link>https://example.com/other</link>
    </item></channel></rss>"""
    entries = parse_feed(xml)
    assert len(entries) == 1
    assert entries[0].name == "titlepkg"
    assert entries[0].version == "3.4.5"


def test_parse_skips_item_without_name():
    xml = "<rss><channel><item><link>https://x/</link></item></channel></rss>"
    assert parse_feed(xml) == []


def test_parse_empty_and_malformed_are_safe():
    assert parse_feed("") == []
    assert parse_feed("<not-valid-xml") == []


# ── fetch_feed ───────────────────────────────────────────────────────────────

def test_fetch_named_shortcut_resolves_to_pypi_url():
    resp = MagicMock()
    resp.__enter__.return_value = resp
    resp.read.return_value = SAMPLE_RSS.encode("utf-8")
    with patch("urllib.request.urlopen", return_value=resp) as mock_open:
        text = fetch_feed("updates")
    assert "evilpkg" in text
    called_url = mock_open.call_args[0][0]
    assert called_url == FEED_URLS["updates"]


def test_fetch_local_file(tmp_path):
    f = tmp_path / "feed.xml"
    f.write_text(SAMPLE_RSS)
    assert "evilpkg" in fetch_feed(str(f))


def test_fetch_network_error_returns_empty():
    with patch("urllib.request.urlopen", side_effect=RuntimeError("boom")):
        assert fetch_feed("https://pypi.org/rss/updates.xml") == ""


def test_fetch_missing_source_returns_empty():
    assert fetch_feed("") == ""
    assert fetch_feed("/no/such/feed.xml") == ""


def test_fetch_directory_path_returns_empty(tmp_path):
    d = tmp_path / "adir"
    d.mkdir()
    assert fetch_feed(str(d)) == ""
