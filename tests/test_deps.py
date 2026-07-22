"""Tests for pipguard.deps — dependency file parsing."""


from pipguard.deps import _parse_pyproject_toml, _parse_setup_cfg, parse_dependencies_file


class TestParseDependenciesFile:
    def test_returns_none_for_requirements_txt(self, tmp_path):
        req = tmp_path / "requirements.txt"
        req.write_text("requests>=2.28\nnumpy==1.26.3\n")
        result = parse_dependencies_file(str(req))
        assert result is None

    def test_returns_none_for_unknown_file(self, tmp_path):
        f = tmp_path / "deps.txt"
        f.write_text("something\n")
        result = parse_dependencies_file(str(f))
        assert result is None

    def test_parses_pyproject_toml(self, tmp_path):
        toml = tmp_path / "pyproject.toml"
        toml.write_text(
            '[project]\n'
            'name = "my-pkg"\n'
            'dependencies = [\n'
            '    "requests>=2.28",\n'
            '    "click>=8.0",\n'
            ']\n'
        )
        result = parse_dependencies_file(str(toml))
        assert result == ["requests>=2.28", "click>=8.0"]

    def test_parses_setup_cfg(self, tmp_path):
        cfg = tmp_path / "setup.cfg"
        cfg.write_text(
            "[metadata]\n"
            "name = my-pkg\n"
            "\n"
            "[options]\n"
            "install_requires =\n"
            "    requests>=2.28\n"
            "    click>=8.0\n"
            "\n"
            "[options.extras_require]\n"
            "dev =\n"
            "    pytest\n"
        )
        result = parse_dependencies_file(str(cfg))
        assert result == ["requests>=2.28", "click>=8.0"]

    def test_parses_setup_cfg_with_extras(self, tmp_path):
        cfg = tmp_path / "setup.cfg"
        cfg.write_text(
            "[options]\n"
            "install_requires =\n"
            "    requests>=2.28\n"
            "\n"
            "[options.extras_require]\n"
            "dev =\n"
            "    pytest\n"
            "    ruff\n"
        )
        result = parse_dependencies_file(str(cfg), extras=["dev"])
        assert "requests>=2.28" in result
        assert "pytest" in result
        assert "ruff" in result


class TestParsePyprojectToml:
    def test_empty_file(self, tmp_path):
        toml = tmp_path / "pyproject.toml"
        toml.write_text("")
        result = _parse_pyproject_toml(str(toml))
        assert result == []

    def test_no_dependencies_key(self, tmp_path):
        toml = tmp_path / "pyproject.toml"
        toml.write_text('[project]\nname = "x"\n')
        result = _parse_pyproject_toml(str(toml))
        assert result == []

    def test_basic_dependencies(self, tmp_path):
        toml = tmp_path / "pyproject.toml"
        toml.write_text(
            '[project]\n'
            'name = "my-pkg"\n'
            'dependencies = [\n'
            '    "requests>=2.28",\n'
            '    "numpy",\n'
            '    "pandas>=1.5,<2.0",\n'
            ']\n'
        )
        result = _parse_pyproject_toml(str(toml))
        assert result == ["requests>=2.28", "numpy", "pandas>=1.5,<2.0"]

    def test_inline_dependencies(self, tmp_path):
        toml = tmp_path / "pyproject.toml"
        toml.write_text(
            '[project]\n'
            'dependencies = ["requests", "click"]\n'
        )
        result = _parse_pyproject_toml(str(toml))
        assert result == ["requests", "click"]

    def test_optional_dependencies(self, tmp_path):
        toml = tmp_path / "pyproject.toml"
        toml.write_text(
            '[project]\n'
            'dependencies = ["requests"]\n'
            '\n'
            '[project.optional-dependencies]\n'
            'dev = [\n'
            '    "pytest",\n'
            '    "ruff",\n'
            ']\n'
            'docs = [\n'
            '    "mkdocs",\n'
            ']\n'
        )
        # Without extras
        result = _parse_pyproject_toml(str(toml))
        assert result == ["requests"]

        # With extras
        result = _parse_pyproject_toml(str(toml), extras=["dev"])
        assert "requests" in result
        assert "pytest" in result
        assert "ruff" in result
        assert "mkdocs" not in result

    def test_multiple_extras(self, tmp_path):
        toml = tmp_path / "pyproject.toml"
        toml.write_text(
            '[project]\n'
            'dependencies = ["base"]\n'
            '\n'
            '[project.optional-dependencies]\n'
            'dev = ["pytest"]\n'
            'docs = ["mkdocs"]\n'
        )
        result = _parse_pyproject_toml(str(toml), extras=["dev", "docs"])
        assert "base" in result
        assert "pytest" in result
        assert "mkdocs" in result


class TestParseSetupCfg:
    def test_empty_file(self, tmp_path):
        cfg = tmp_path / "setup.cfg"
        cfg.write_text("")
        result = _parse_setup_cfg(str(cfg))
        assert result == []

    def test_no_install_requires(self, tmp_path):
        cfg = tmp_path / "setup.cfg"
        cfg.write_text("[metadata]\nname = my-pkg\n")
        result = _parse_setup_cfg(str(cfg))
        assert result == []

    def test_multiline_install_requires(self, tmp_path):
        cfg = tmp_path / "setup.cfg"
        cfg.write_text(
            "[options]\n"
            "install_requires =\n"
            "    requests>=2.28\n"
            "    click>=8.0\n"
            "    numpy\n"
        )
        result = _parse_setup_cfg(str(cfg))
        assert result == ["requests>=2.28", "click>=8.0", "numpy"]

    def test_with_extras(self, tmp_path):
        cfg = tmp_path / "setup.cfg"
        cfg.write_text(
            "[options]\n"
            "install_requires =\n"
            "    requests\n"
            "\n"
            "[options.extras_require]\n"
            "test =\n"
            "    pytest\n"
            "    coverage\n"
            "docs =\n"
            "    sphinx\n"
        )
        result = _parse_setup_cfg(str(cfg), extras=["test"])
        assert "requests" in result
        assert "pytest" in result
        assert "coverage" in result
        assert "sphinx" not in result
