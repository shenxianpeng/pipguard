"""Data models for pipguard risk findings."""

from dataclasses import dataclass, field
from enum import Enum
from typing import List, Optional


class RiskLevel(Enum):
    CLEAN = 0
    LOW = 1
    MEDIUM = 2
    HIGH = 3
    CRITICAL = 4

    def __str__(self) -> str:
        return self.name


@dataclass
class Finding:
    """A single risk finding from scanning a file."""

    level: RiskLevel
    file_path: str
    line: int
    description: str
    snippet: Optional[str] = None

    def __str__(self) -> str:
        loc = f"{self.file_path}:{self.line}" if self.line else self.file_path
        return f"[{self.level}] {loc}: {self.description}"


@dataclass
class PackageScanResult:
    """Scan results for a single package."""

    package_name: str
    version: str
    findings: List[Finding] = field(default_factory=list)
    is_allowlisted: bool = False
    is_binary_only: bool = False

    @property
    def max_level(self) -> RiskLevel:
        if not self.findings:
            return RiskLevel.CLEAN
        return max((f.level for f in self.findings), key=lambda l: l.value)

    @property
    def effective_level(self) -> RiskLevel:
        """Level after applying allowlist: HIGH→MEDIUM for allowlisted, CRITICAL never reduced.

        Binary-only packages with no other findings are elevated to MEDIUM so
        the confirmation gate fires — pipguard's scan promise cannot be
        fulfilled for packages with no Python source (TODO-5, option A).
        """
        level = self.max_level
        if self.is_allowlisted and level == RiskLevel.HIGH:
            return RiskLevel.MEDIUM
        if self.is_binary_only and level == RiskLevel.CLEAN:
            return RiskLevel.MEDIUM
        return level
