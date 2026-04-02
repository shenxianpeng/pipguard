"""
Tests for pipguard.extractor — archive extraction and file collection.

Critical paths tested:
  1. extract_archive handles .whl (zip) correctly
  2. extract_archive handles .tar.gz correctly
  3. extract_archive handles corrupt archives gracefully (returns None)
  4. extract_archive prevents path traversal in .tar.gz
  5. collect_scannable_files yields .py files
  6. collect_scannable_files yields .pth files (attack vector)
  7. collect_scannable_files yields hook files (setup.py, setup.cfg, pyproject.toml)
  8. collect_scannable_files skips __pycache__ and .git
  9. has_python_source returns True for .py files
 10. has_python_source returns False for binary-only directory
"""

import os
import sys
import tarfile
import tempfile
import zipfile

import pytest

sys.path.insert(0, os.path.join(os.path.dirname(__file__), ".."))

from pipguard.extractor import (
    collect_binary_extension_files,
    collect_scannable_files,
    extract_archive,
    has_python_source,
)


# ── extract_archive ──────────────────────────────────────────────────────────

class TestExtractArchive:

    def test_extract_wheel(self, tmp_path):
        """A .whl file (zip archive) is extracted to a subdirectory."""
        whl = tmp_path / "mypkg-1.0-py3-none-any.whl"
        with zipfile.ZipFile(str(whl), "w") as zf:
            zf.writestr("mypkg/__init__.py", "# hello\n")
        result = extract_archive(str(whl), str(tmp_path))
        assert result is not None
        assert os.path.isdir(result)
        assert os.path.exists(os.path.join(result, "mypkg", "__init__.py"))

    def test_extract_tar_gz(self, tmp_path):
        """A .tar.gz sdist is extracted correctly."""
        tgz = tmp_path / "mypkg-1.0.tar.gz"
        with tarfile.open(str(tgz), "w:gz") as tf:
            info = tarfile.TarInfo(name="mypkg-1.0/setup.py")
            content = b"from setuptools import setup; setup()\n"
            info.size = len(content)
            import io
            tf.addfile(info, io.BytesIO(content))
        result = extract_archive(str(tgz), str(tmp_path))
        assert result is not None
        assert os.path.isdir(result)

    def test_extract_corrupt_zip_returns_none(self, tmp_path):
        """Corrupt zip returns None, does not raise."""
        bad = tmp_path / "bad-1.0-py3-none-any.whl"
        bad.write_bytes(b"not a zip file")
        result = extract_archive(str(bad), str(tmp_path))
        assert result is None

    def test_extract_corrupt_tar_returns_none(self, tmp_path):
        """Corrupt tar.gz returns None, does not raise."""
        bad = tmp_path / "bad-1.0.tar.gz"
        bad.write_bytes(b"not a tar file")
        result = extract_archive(str(bad), str(tmp_path))
        assert result is None

    def test_extract_unsupported_extension_returns_none(self, tmp_path):
        """Unsupported extension returns None."""
        f = tmp_path / "mypkg-1.0.egg"
        f.write_bytes(b"data")
        result = extract_archive(str(f), str(tmp_path))
        assert result is None

    def test_path_traversal_prevented(self, tmp_path):
        """Tar members with ../ paths must not escape the extraction directory."""
        tgz = tmp_path / "evil-1.0.tar.gz"
        sentinel = tmp_path / "escaped.txt"

        with tarfile.open(str(tgz), "w:gz") as tf:
            import io
            info = tarfile.TarInfo(name="../escaped.txt")
            payload = b"pwned\n"
            info.size = len(payload)
            tf.addfile(info, io.BytesIO(payload))

        dest = tmp_path / "extract_dest"
        dest.mkdir()
        extract_archive(str(tgz), str(dest))

        # The file must NOT have been written outside the dest directory
        assert not sentinel.exists(), (
            "Path traversal succeeded — escaped.txt was written outside extract_dest"
        )


# ── collect_scannable_files ──────────────────────────────────────────────────

class TestCollectScannableFiles:

    def _make_tree(self, root, files):
        """Helper: create a directory tree from {rel_path: content} dict."""
        for rel, content in files.items():
            p = root / rel
            p.parent.mkdir(parents=True, exist_ok=True)
            p.write_text(content)

    def test_yields_py_files(self, tmp_path):
        self._make_tree(tmp_path, {
            "mypkg/__init__.py": "# init\n",
            "mypkg/utils.py": "# utils\n",
        })
        paths = [p for p, _ in collect_scannable_files(str(tmp_path))]
        basenames = {os.path.basename(p) for p in paths}
        assert "__init__.py" in basenames
        assert "utils.py" in basenames

    def test_yields_pth_files(self, tmp_path):
        """Regression: .pth files must be yielded even when no .py files exist."""
        self._make_tree(tmp_path, {
            "attack.pth": 'import os;os.system("id")\n',
        })
        paths = [p for p, _ in collect_scannable_files(str(tmp_path))]
        assert any(p.endswith(".pth") for p in paths), (
            "collect_scannable_files must yield .pth files"
        )

    def test_pth_files_marked_as_hook(self, tmp_path):
        self._make_tree(tmp_path, {"site.pth": "/usr/lib/python\n"})
        results = list(collect_scannable_files(str(tmp_path)))
        pth_results = [(p, h) for p, h in results if p.endswith(".pth")]
        assert pth_results, "Expected at least one .pth result"
        assert all(h for _, h in pth_results), ".pth files must be is_hook=True"

    def test_setup_py_is_hook(self, tmp_path):
        self._make_tree(tmp_path, {"setup.py": "from setuptools import setup\n"})
        results = list(collect_scannable_files(str(tmp_path)))
        for p, is_hook in results:
            if os.path.basename(p) == "setup.py":
                assert is_hook, "setup.py must be is_hook=True"
                break
        else:
            pytest.fail("setup.py not found in scannable files")

    def test_regular_py_is_not_hook(self, tmp_path):
        self._make_tree(tmp_path, {"mypkg/utils.py": "x = 1\n"})
        results = list(collect_scannable_files(str(tmp_path)))
        for p, is_hook in results:
            if os.path.basename(p) == "utils.py":
                assert not is_hook, "Regular .py must be is_hook=False"
                break
        else:
            pytest.fail("utils.py not found in scannable files")

    def test_skips_pycache(self, tmp_path):
        self._make_tree(tmp_path, {
            "mypkg/__pycache__/utils.cpython-311.pyc": "junk",
            "mypkg/utils.py": "x = 1\n",
        })
        paths = [p for p, _ in collect_scannable_files(str(tmp_path))]
        assert not any("__pycache__" in p for p in paths)

    def test_skips_test_directories(self, tmp_path):
        self._make_tree(tmp_path, {
            "mypkg/utils.py": "x = 1\n",
            "tests/test_utils.py": "def test_x(): pass\n",
            "test/test_utils.py": "def test_x(): pass\n",
        })
        paths = [p for p, _ in collect_scannable_files(str(tmp_path))]
        assert not any(
            os.sep + "tests" + os.sep in p or os.sep + "test" + os.sep in p
            for p in paths
        )

    def test_empty_directory_yields_nothing(self, tmp_path):
        results = list(collect_scannable_files(str(tmp_path)))
        assert results == []


# ── has_python_source ────────────────────────────────────────────────────────

class TestHasPythonSource:

    def test_returns_true_for_py_file(self, tmp_path):
        (tmp_path / "mod.py").write_text("x = 1\n")
        assert has_python_source(str(tmp_path)) is True

    def test_returns_false_for_binary_only(self, tmp_path):
        (tmp_path / "mod.so").write_bytes(b"\x7fELF")
        assert has_python_source(str(tmp_path)) is False

    def test_returns_false_for_empty_dir(self, tmp_path):
        assert has_python_source(str(tmp_path)) is False


# ── collect_binary_extension_files ──────────────────────────────────────────

class TestCollectBinaryExtensionFiles:
    """TODO-1: collect_binary_extension_files enumerates .so/.pyd/.dylib files."""

    def test_empty_dir_returns_empty(self, tmp_path):
        assert collect_binary_extension_files(str(tmp_path)) == []

    def test_py_only_returns_empty(self, tmp_path):
        (tmp_path / "mod.py").write_text("x = 1\n")
        assert collect_binary_extension_files(str(tmp_path)) == []

    def test_so_file_returned(self, tmp_path):
        so = tmp_path / "_ext.so"
        so.write_bytes(b"\x7fELF")
        result = collect_binary_extension_files(str(tmp_path))
        assert str(so) in result

    def test_pyd_file_returned(self, tmp_path):
        pyd = tmp_path / "_ext.pyd"
        pyd.write_bytes(b"MZ")
        result = collect_binary_extension_files(str(tmp_path))
        assert str(pyd) in result

    def test_dylib_file_returned(self, tmp_path):
        dylib = tmp_path / "libfoo.dylib"
        dylib.write_bytes(b"\xcf\xfa\xed\xfe")
        result = collect_binary_extension_files(str(tmp_path))
        assert str(dylib) in result

    def test_skips_test_directories(self, tmp_path):
        """Binary extensions inside test directories are ignored."""
        test_dir = tmp_path / "tests"
        test_dir.mkdir()
        (test_dir / "_ext.so").write_bytes(b"\x7fELF")
        assert collect_binary_extension_files(str(tmp_path)) == []

    def test_finds_nested_so_files(self, tmp_path):
        pkg_dir = tmp_path / "mypkg"
        pkg_dir.mkdir()
        so = pkg_dir / "_fast.so"
        so.write_bytes(b"\x7fELF")
        result = collect_binary_extension_files(str(tmp_path))
        assert str(so) in result
