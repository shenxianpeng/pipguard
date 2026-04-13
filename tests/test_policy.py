from pipguard.policy import load_policy, _parse_policy_toml


def test_load_policy_defaults_when_missing(tmp_path):
    p = tmp_path / "missing.toml"
    policy = load_policy(str(p))
    assert policy.require_hashes is False
    assert policy.binary_only == "prompt"


def test_load_policy_install_and_intel_sections(tmp_path):
    p = tmp_path / "pipguard-policy.toml"
    p.write_text(
        "[install]\n"
        "require_hashes = true\n"
        "allow_vcs_pinned = false\n"
        "allow_direct_url_pinned = false\n"
        "binary_only = 'block'\n"
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


def test_load_policy_invalid_binary_only_falls_back(tmp_path):
    p = tmp_path / "pipguard-policy.toml"
    p.write_text("[install]\nbinary_only = 'weird'\n")
    policy = load_policy(str(p))
    assert policy.binary_only == "prompt"


def test_parse_policy_toml_fallback_parser_branch():
    data = _parse_policy_toml(
        "[install]\nrequire_hashes = true\nbinary_only = 'allow'\n"
    )
    assert "install" in data
