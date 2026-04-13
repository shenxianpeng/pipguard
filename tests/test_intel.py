import json
from unittest.mock import patch, MagicMock

from pipguard.intel import load_intel_feed


def test_load_intel_feed_from_local_file(tmp_path):
    feed = tmp_path / "feed.json"
    feed.write_text(json.dumps({
        "blocked": [{"name": "evilpkg", "version": "1.2.3", "reason": "malware"}]
    }))
    rules = load_intel_feed(str(feed))
    assert rules[("evilpkg", "1.2.3")] == "malware"


def test_load_intel_feed_invalid_json_returns_empty(tmp_path):
    feed = tmp_path / "feed.json"
    feed.write_text("{not-json")
    assert load_intel_feed(str(feed)) == {}


def test_load_intel_feed_missing_source_returns_empty():
    assert load_intel_feed("") == {}
    assert load_intel_feed("/no/such/file.json") == {}


def test_load_intel_feed_http_success():
    payload = b'{"blocked":[{"name":"evil","version":"9.9.9","reason":"x"}]}'
    mock_resp = MagicMock()
    mock_resp.__enter__.return_value = mock_resp
    mock_resp.read.return_value = payload
    with patch("urllib.request.urlopen", return_value=mock_resp):
        rules = load_intel_feed("https://example.org/feed.json")
    assert ("evil", "9.9.9") in rules


def test_load_intel_feed_http_failure_returns_empty():
    with patch("urllib.request.urlopen", side_effect=RuntimeError("boom")):
        assert load_intel_feed("https://example.org/feed.json") == {}
