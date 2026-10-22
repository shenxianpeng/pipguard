import pytest

from pipguard import policy as policy_module
from pipguard.policy import Policy, load_policy, _parse_policy_toml

try:
    import tomllib as _tomllib
except ModuleNotFoundError:  # Python 3.10: pytest depends on tomli, which has the same API
    import tomli as _tomllib


@pytest.fixture
def stdlib_toml(monkeypatch):
    """Force the tomllib code path (on 3.10 tomli stands in for the stdlib module)."""
    monkeypatch.setattr(policy_module, "tomllib", _tomllib)


@pytest.fixture
def fallback_toml(monkeypatch):
    """Force the stdlib-free fallback parser that Python 3.10 relies on."""
    monkeypatch.setattr(policy_module, "tomllib", None)


@pytest.fixture(params=["tomllib", "fallback"])
def any_toml_backend(request, monkeypatch):
    """Run a test against both policy parsers so they stay behaviourally equivalent."""
    monkeypatch.setattr(
        policy_module, "tomllib", _tomllib if request.param == "tomllib" else None
    )
    return request.param


def test_load_policy_defaults_when_missing(tmp_path):
    p = tmp_path / "missing.toml"
    policy = load_policy(str(p))
    assert policy.require_hashes is False
    assert policy.binary_only == "prompt"
    assert policy.sandbox is False


def test_load_policy_sandbox_key(tmp_path):
    p = tmp_path / "pipguard.toml"
    p.write_text("[install]\nsandbox = true\n")
    assert load_policy(str(p)).sandbox is True


def test_load_policy_install_and_intel_sections(tmp_path):
    p = tmp_path / "pipguard.toml"
    p.write_text(
        "[install]\n"
        "require_hashes = true\n"
        "allow_vcs_pinned = false\n"
        "allow_direct_url_pinned = false\n"
        "binary_only = 'block'\n"
        "\n"
        "[allowlist]\n"
        "seed = ['corp-auth-sdk', 'internal-keyring']\n"
        "\n"
        "[intel]\n"
        "feed = 'feed.json'\n"
        "enforce = true\n"
    )
    policy = load_policy(str(p))
    assert policy.require_hashes is True
    assert policy.allow_vcs_pinned is False
    assert policy.allow_direct_url_pinned is False
    assert policy.binary_only == "block"
    assert policy.intel_feed == "feed.json"
    assert policy.intel_enforce is True
    assert policy.seed_allowlist == ["corp-auth-sdk", "internal-keyring"]


def test_load_policy_invalid_binary_only_falls_back(tmp_path):
    p = tmp_path / "pipguard.toml"
    p.write_text("[install]\nbinary_only = 'weird'\n")
    policy = load_policy(str(p))
    assert policy.binary_only == "prompt"


def test_parse_policy_toml_fallback_parser_branch():
    data = _parse_policy_toml(
        "[install]\nrequire_hashes = true\nbinary_only = 'allow'\n"
    )
    assert "install" in data


def test_load_policy_unreadable_file_returns_defaults(tmp_path):
    """A path that exists but cannot be read as text (a directory) → OSError → defaults."""
    assert load_policy(str(tmp_path)) == Policy()


def test_load_policy_empty_file_returns_defaults(tmp_path, any_toml_backend):
    p = tmp_path / "pipguard.toml"
    p.write_text("")
    assert load_policy(str(p)) == Policy()


def test_load_policy_invalid_toml_returns_defaults(tmp_path, stdlib_toml):
    p = tmp_path / "pipguard.toml"
    p.write_text("[install\nrequire_hashes = \n")
    assert _parse_policy_toml(p.read_text()) == {}
    assert load_policy(str(p)) == Policy()


def test_load_policy_seed_not_a_list_is_ignored(tmp_path, any_toml_backend):
    p = tmp_path / "pipguard.toml"
    p.write_text("[allowlist]\nseed = 'corp-auth-sdk'\n")
    assert load_policy(str(p)).seed_allowlist == []


def test_load_policy_osv_section(tmp_path, any_toml_backend):
    p = tmp_path / "pipguard.toml"
    p.write_text("[osv]\nenabled = true\nfail_on_vuln = true\n")
    policy = load_policy(str(p))
    assert policy.osv_enabled is True
    assert policy.osv_fail_on_vuln is True


class TestFallbackParser:
    """The tiny TOML-subset parser used when tomllib is unavailable (Python 3.10)."""

    def test_parses_sections_scalars_and_lists(self, fallback_toml):
        data = _parse_policy_toml(
            "# leading comment\n"
            "orphan = true\n"  # key before any [section] is ignored
            "\n"
            "[install]\n"
            "require_hashes = true\n"
            "sandbox = FALSE\n"
            "binary_only = 'block'\n"
            "retries = 3\n"
            "not a key value pair\n"
            "\n"
            "[allowlist]\n"
            "seed = [\"corp-auth-sdk\", 'internal-keyring', bare]\n"
            "empty = []\n"
            "\n"
            "[intel]\n"
            'feed = "https://example.org/feed.json"\n'
        )
        assert data == {
            "install": {
                "require_hashes": True,
                "sandbox": False,
                "binary_only": "block",
                "retries": "3",
            },
            "allowlist": {
                "seed": ["corp-auth-sdk", "internal-keyring", "bare"],
                "empty": [],
            },
            "intel": {"feed": "https://example.org/feed.json"},
        }

    def test_load_policy_matches_tomllib_result(self, tmp_path, monkeypatch):
        p = tmp_path / "pipguard.toml"
        p.write_text(
            "[install]\n"
            "require_hashes = true\n"
            "allow_vcs_pinned = false\n"
            "allow_direct_url_pinned = false\n"
            "binary_only = 'block'\n"
            "sandbox = true\n"
            "\n"
            "[allowlist]\n"
            "seed = ['corp-auth-sdk', \"internal-keyring\"]\n"
            "\n"
            "[intel]\n"
            "feed = 'feed.json'\n"
            "enforce = true\n"
            "\n"
            "[osv]\n"
            "enabled = true\n"
            "fail_on_vuln = true\n"
        )
        monkeypatch.setattr(policy_module, "tomllib", _tomllib)
        expected = load_policy(str(p))
        assert expected != Policy()  # guard: the file really changes every section

        monkeypatch.setattr(policy_module, "tomllib", None)
        assert load_policy(str(p)) == expected
