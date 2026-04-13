"""Policy-as-code support for pipguard."""

from dataclasses import dataclass, field
from pathlib import Path
from typing import List, Optional

try:  # Python 3.11+
    import tomllib
except ModuleNotFoundError:  # pragma: no cover
    tomllib = None


@dataclass(frozen=True)
class Policy:
    require_hashes: bool = False
    allow_vcs_pinned: bool = True
    allow_direct_url_pinned: bool = True
    binary_only: str = "prompt"  # prompt | block | allow
    intel_feed: str = ""
    intel_enforce: bool = False
    seed_allowlist: List[str] = field(default_factory=list)


def load_policy(path: Optional[str]) -> Policy:
    """Load policy TOML from explicit path or default pipguard.toml."""
    candidate = Path(path) if path else Path("pipguard.toml")
    if not candidate.exists():
        return Policy()

    try:
        text = candidate.read_text(encoding="utf-8")
    except OSError:
        return Policy()

    data = _parse_policy_toml(text)
    if not data:
        return Policy()

    install = data.get("install", {})
    binary_only = str(install.get("binary_only", "prompt")).lower()
    if binary_only not in {"prompt", "block", "allow"}:
        binary_only = "prompt"

    allowlist = data.get("allowlist", {})
    configured_allowlist = allowlist.get("seed", [])
    if not isinstance(configured_allowlist, list):
        configured_allowlist = []

    intel = data.get("intel", {})

    return Policy(
        require_hashes=bool(install.get("require_hashes", False)),
        allow_vcs_pinned=bool(install.get("allow_vcs_pinned", True)),
        allow_direct_url_pinned=bool(install.get("allow_direct_url_pinned", True)),
        binary_only=binary_only,
        intel_feed=str(intel.get("feed", "")).strip(),
        intel_enforce=bool(intel.get("enforce", False)),
        seed_allowlist=[str(item) for item in configured_allowlist if str(item).strip()],
    )


def _parse_policy_toml(text: str) -> dict:
    """Parse policy TOML via tomllib if available, else tiny fallback parser."""
    if tomllib is not None:
        try:
            return tomllib.loads(text)
        except tomllib.TOMLDecodeError:
            return {}

    section = None
    data = {}
    for raw in text.splitlines():
        line = raw.strip()
        if not line or line.startswith("#"):
            continue
        if line.startswith("[") and line.endswith("]"):
            section = line[1:-1].strip()
            data.setdefault(section, {})
            continue
        if "=" not in line or section is None:
            continue
        key, value = [x.strip() for x in line.split("=", 1)]
        if value.lower() in ("true", "false"):
            parsed = value.lower() == "true"
        elif value.startswith("[") and value.endswith("]"):
            items = []
            inner = value[1:-1].strip()
            if inner:
                for token in inner.split(","):
                    token = token.strip()
                    if (token.startswith('"') and token.endswith('"')) or (
                        token.startswith("'") and token.endswith("'")
                    ):
                        token = token[1:-1]
                    items.append(token)
            parsed = items
        elif (value.startswith('"') and value.endswith('"')) or (
            value.startswith("'") and value.endswith("'")
        ):
            parsed = value[1:-1]
        else:
            parsed = value
        data[section][key] = parsed
    return data
