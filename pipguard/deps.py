"""Parse dependencies from various Python project file formats.

Supports:
- requirements.txt (standard pip format)
- pyproject.toml [project.dependencies] and [project.optional-dependencies]
- setup.cfg [options] install_requires

All parsers return a list of PEP 508 requirement strings suitable for
passing to `pip download`.
"""

from pathlib import Path
from typing import List, Optional

try:  # Python 3.11+
    import tomllib
except ModuleNotFoundError:  # pragma: no cover
    tomllib = None  # type: ignore[assignment]


def parse_dependencies_file(filepath: str, extras: Optional[List[str]] = None) -> Optional[List[str]]:
    """Parse dependencies from a file based on its extension.

    Returns a list of requirement strings, or None if the file format
    is not a recognized dependency file (i.e., it's a plain requirements.txt
    and should be passed through to pip directly).

    Args:
        filepath: Path to the dependency file.
        extras: Optional list of extras/optional-dependency groups to include.
    """
    p = Path(filepath)
    name = p.name.lower()

    if name == "pyproject.toml":
        return _parse_pyproject_toml(filepath, extras)
    if name == "setup.cfg":
        return _parse_setup_cfg(filepath, extras)

    # Not a recognized structured file — return None to signal "use as-is"
    return None


def _parse_pyproject_toml(filepath: str, extras: Optional[List[str]] = None) -> List[str]:
    """Extract dependencies from pyproject.toml.

    Reads [project.dependencies] and optionally [project.optional-dependencies].
    """
    text = Path(filepath).read_text(encoding="utf-8")
    data = _parse_toml(text)
    if not data:
        return []

    project = data.get("project", {})
    deps: List[str] = []

    # Main dependencies
    main_deps = project.get("dependencies", [])
    if isinstance(main_deps, list):
        deps.extend(str(d).strip() for d in main_deps if str(d).strip())

    # Optional dependencies (extras)
    if extras:
        opt_deps = project.get("optional-dependencies", {})
        for extra in extras:
            extra_deps = opt_deps.get(extra, [])
            if isinstance(extra_deps, list):
                deps.extend(str(d).strip() for d in extra_deps if str(d).strip())

    return deps


def _parse_setup_cfg(filepath: str, extras: Optional[List[str]] = None) -> List[str]:
    """Extract dependencies from setup.cfg [options] install_requires."""
    text = Path(filepath).read_text(encoding="utf-8")
    deps: List[str] = []

    section = None
    in_install_requires = False
    in_extras_require = False
    current_extra = None
    target_extras = set(extras or [])

    for raw in text.splitlines():
        line = raw.rstrip()

        # Section header
        if line.startswith("[") and "]" in line:
            section = line.split("]")[0][1:].strip()
            in_install_requires = False
            in_extras_require = False
            current_extra = None
            continue

        if section == "options":
            if line.strip().lower() == "install_requires =":
                in_install_requires = True
                continue
            if line.strip().lower().startswith("install_requires"):
                # Single-line: install_requires = pkg1; pkg2
                _, _, value = line.partition("=")
                value = value.strip()
                if value:
                    in_install_requires = True
                    # Check for single-line value
                    for dep in value.split("\n"):
                        dep = dep.strip()
                        if dep:
                            deps.append(dep)
                continue
            if in_install_requires:
                if line and line[0] in (" ", "\t"):
                    dep = line.strip()
                    if dep:
                        deps.append(dep)
                else:
                    in_install_requires = False

        if section == "options.extras_require" and target_extras:
            if "=" in line and line[0] not in (" ", "\t"):
                key, _, value = line.partition("=")
                current_extra = key.strip()
                in_extras_require = current_extra in target_extras
                value = value.strip()
                if in_extras_require and value:
                    for dep in value.split("\n"):
                        dep = dep.strip()
                        if dep:
                            deps.append(dep)
            elif in_extras_require and line and line[0] in (" ", "\t"):
                dep = line.strip()
                if dep:
                    deps.append(dep)
            elif not line.strip():
                continue
            else:
                in_extras_require = False

    return deps


def _parse_toml(text: str) -> dict:
    """Parse TOML text using tomllib (3.11+) or minimal fallback."""
    if tomllib is not None:
        try:
            return tomllib.loads(text)
        except Exception:
            return {}

    # Minimal fallback for Python 3.10 — handles simple cases
    return _minimal_toml_parse(text)


def _minimal_toml_parse(text: str) -> dict:
    """Minimal TOML parser for pyproject.toml dependency extraction.

    Only handles the subset needed: [project] dependencies = [...] lists.
    """
    data: dict = {}
    current_section: Optional[str] = None
    in_array = False
    array_key = ""
    array_items: List[str] = []

    for raw in text.splitlines():
        line = raw.strip()

        if not line or line.startswith("#"):
            if in_array:
                continue
            continue

        # Section headers
        if line.startswith("[") and line.endswith("]") and not in_array:
            current_section = line[1:-1].strip()
            _ensure_nested(data, current_section)
            continue

        if current_section is None:
            continue

        # Handle multi-line arrays
        if in_array:
            if line == "]":
                _set_nested(data, current_section, array_key, array_items)
                in_array = False
                array_items = []
                continue
            # Parse array item (strip quotes and trailing comma)
            item = line.rstrip(",").strip()
            if (item.startswith('"') and item.endswith('"')) or (
                item.startswith("'") and item.endswith("'")
            ):
                item = item[1:-1]
            if item:
                array_items.append(item)
            continue

        # Key = value
        if "=" in line:
            key, _, value = line.partition("=")
            key = key.strip()
            value = value.strip()

            if value == "[":
                in_array = True
                array_key = key
                array_items = []
            elif value.startswith("[") and value.endswith("]"):
                # Inline array
                inner = value[1:-1].strip()
                items = []
                if inner:
                    for token in inner.split(","):
                        token = token.strip().rstrip(",")
                        if (token.startswith('"') and token.endswith('"')) or (
                            token.startswith("'") and token.endswith("'")
                        ):
                            token = token[1:-1]
                        if token:
                            items.append(token)
                _set_nested(data, current_section, key, items)
            elif (value.startswith('"') and value.endswith('"')) or (
                value.startswith("'") and value.endswith("'")
            ):
                _set_nested(data, current_section, key, value[1:-1])
            elif value.lower() in ("true", "false"):
                _set_nested(data, current_section, key, value.lower() == "true")
            else:
                _set_nested(data, current_section, key, value)

    return data


def _ensure_nested(data: dict, dotted_key: str) -> dict:
    """Ensure nested dict structure exists for a dotted section key."""
    parts = dotted_key.split(".")
    current = data
    for part in parts:
        if part not in current:
            current[part] = {}
        current = current[part]
    return current


def _set_nested(data: dict, section: str, key: str, value: object) -> None:
    """Set a value in a nested dict structure."""
    container = _ensure_nested(data, section)
    container[key] = value
