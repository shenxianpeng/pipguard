"""pipguard CLI — scan Python packages before installing them.

Usage:
    pipguard install <package> [<package> ...]
    pipguard install -r requirements.txt

Exit codes:
    0  Clean — all packages scanned CLEAN, install succeeded
    1  Blocked — CRITICAL or HIGH risk detected (without --force)
    2  Error — download failed, unsupported format, or scan error
"""

import argparse
import concurrent.futures
import os
import re
import sys
import tempfile
from typing import List, Optional, Tuple

from . import __version__
from .aggregator import aggregate_findings, check_package_name_for_homoglyph, print_findings_report
from .cleanup import install_signal_handlers, register_temp_dir
from .downloader import download_packages
from .extractor import collect_binary_extension_files, collect_scannable_files, extract_archive
from .installer import install_from_local
from .intel import load_intel_feed
from .models import Finding, PackageScanResult, RiskLevel
from .policy import load_policy
from .scanner import scan_binary_extensions, scan_pth_file, scan_python_file


# ── Package name extraction ──────────────────────────────────────────────────

def _pkg_name_from_filename(archive_path: str) -> str:
    """
    Extract the distribution name from a wheel or sdist filename.

    Wheel: {name}-{version}-{py}-{abi}-{platform}.whl
    Sdist: {name}-{version}.tar.gz | .zip | .tar.bz2

    Stops at the first component that starts with a digit (the version).
    """
    fname = os.path.basename(archive_path)
    for ext in (".whl", ".tar.gz", ".tar.bz2", ".tgz", ".zip"):
        if fname.endswith(ext):
            fname = fname[: -len(ext)]
            break
    parts = fname.split("-")
    name_parts = []
    for part in parts:
        if part and part[0].isdigit():
            break
        name_parts.append(part)
    return "-".join(name_parts) if name_parts else fname


def _pkg_version_from_filename(archive_path: str) -> str:
    """Extract version from wheel/sdist filename using first digit-starting segment."""
    fname = os.path.basename(archive_path)
    for ext in (".whl", ".tar.gz", ".tar.bz2", ".tgz", ".zip"):
        if fname.endswith(ext):
            fname = fname[: -len(ext)]
            break
    parts = fname.split("-")
    for part in parts:
        if part and part[0].isdigit():
            return part
    return ""


# ── Per-package scan (runs in ThreadPoolExecutor) ───────────────────────────

def _scan_one_package(
    archive_path: str,
    tmp_dir: str,
    extra_allow: List[str],
) -> PackageScanResult:
    """Scan a single downloaded archive. Designed for parallel execution."""
    pkg_name = _pkg_name_from_filename(archive_path)

    # Homoglyph / non-ASCII package name check (TODO-2)
    all_findings: List[Finding] = []
    homoglyph = check_package_name_for_homoglyph(pkg_name)
    if homoglyph:
        all_findings.append(homoglyph)

    extract_dir = extract_archive(archive_path, tmp_dir)
    if extract_dir is None:
        from .models import Finding
        return PackageScanResult(
            package_name=pkg_name,
            version="",
            findings=all_findings + [Finding(
                level=RiskLevel.MEDIUM,
                file_path=archive_path,
                line=0,
                description="Could not extract archive for scanning",
            )],
        )

    has_scannable = False
    for filepath, is_hook in collect_scannable_files(extract_dir):
        has_scannable = True
        if filepath.endswith(".pth"):
            all_findings.extend(scan_pth_file(filepath))
        else:
            all_findings.extend(scan_python_file(filepath, is_hook=is_hook))

    # Binary extension scanning (TODO-1)
    binary_files = collect_binary_extension_files(extract_dir)
    if binary_files:
        all_findings.extend(
            scan_binary_extensions(binary_files, has_python_source=has_scannable)
        )

    if not has_scannable:
        return aggregate_findings(
            pkg_name, all_findings, extra_allow=extra_allow, is_binary_only=True
        )

    return aggregate_findings(pkg_name, all_findings, extra_allow=extra_allow)


# ── requirements.txt validation ─────────────────────────────────────────────

_VCS_PIN_RE = re.compile(r"^(?:git|hg|svn|bzr)\+.+@([A-Fa-f0-9]{7,40})(?:#|$)")
_HASH_FRAG_RE = re.compile(r"#(?:sha256|sha384|sha512)=[A-Fa-f0-9]{32,128}")


def _read_requirement_entries(filepath: str) -> List[Tuple[int, str]]:
    entries: List[Tuple[int, str]] = []
    with open(filepath, "r", encoding="utf-8") as f:
        lineno = 0
        start = 0
        buffer = ""
        for raw in f:
            lineno += 1
            line = raw.rstrip("\n")
            if not buffer:
                start = lineno
            if line.endswith("\\"):
                buffer += line[:-1].rstrip() + " "
                continue
            full = (buffer + line).strip()
            buffer = ""
            if full:
                entries.append((start, full))
    return entries


def _validate_requirements_file(
    filepath: str,
    require_hashes: bool = False,
    allow_vcs_pinned: bool = True,
    allow_direct_url_pinned: bool = True,
) -> int:
    """
    Validate requirements.txt for unsupported formats (Phase 1).
    Returns 0 if OK, 2 if unsupported entries are found.
    """
    unsupported = []
    try:
        entries = _read_requirement_entries(filepath)
        for lineno, line in entries:
            if line.startswith("#") or line.startswith("--"):
                continue
            if line.startswith("-e "):
                print(
                    f"  Note: skipping editable install at line {lineno}: {line}",
                    file=sys.stderr,
                )
                continue

            has_hash = ("--hash=" in line) or bool(_HASH_FRAG_RE.search(line))
            is_vcs = any(line.startswith(prefix) for prefix in ("git+", "hg+", "svn+", "bzr+"))
            is_direct_url = " @ " in line

            if is_vcs:
                if not allow_vcs_pinned:
                    unsupported.append((lineno, line, "VCS dependency disabled by policy"))
                elif not _VCS_PIN_RE.match(line):
                    unsupported.append((lineno, line, "VCS dependency must pin commit hash"))
            elif is_direct_url:
                if not allow_direct_url_pinned:
                    unsupported.append((lineno, line, "direct URL dependency disabled by policy"))
                elif not has_hash:
                    unsupported.append((lineno, line, "direct URL dependency must include hash"))
            elif line.startswith("./") or line.startswith("../") or (
                line.startswith("/") and not line.startswith("-")
            ):
                unsupported.append((lineno, line, "local path dependency"))

            if require_hashes and not has_hash:
                unsupported.append((lineno, line, "missing hash while --require-hashes is enabled"))
    except OSError as exc:
        print(f"Error reading requirements file: {exc}", file=sys.stderr)
        return 2

    if unsupported:
        print(
            "Error: requirements.txt contains unsupported entries (pipguard Phase 1):",
            file=sys.stderr,
        )
        for lineno, entry, reason in unsupported:
            print(f"  Line {lineno}: {entry}  [{reason}]", file=sys.stderr)
        print(
            "\n  Supported: PyPI specifiers, hash-locked deps, and pinned VCS/URL deps.\n"
            "  Not supported: unpinned VCS/URL deps, local paths (./...).",
            file=sys.stderr,
        )
        return 2
    return 0


# ── Install confirmation prompt ──────────────────────────────────────────────

def _confirm_install() -> bool:
    """Ask the user whether to proceed with MEDIUM/LOW findings."""
    try:
        answer = input("\nProceed with installation? [y/N] ").strip().lower()
        return answer in ("y", "yes")
    except (EOFError, KeyboardInterrupt):
        return False


# ── install subcommand ───────────────────────────────────────────────────────

def cmd_install(args) -> int:
    """Implement `pipguard install`. Returns an exit code."""
    install_signal_handlers()

    tmp_dir = tempfile.mkdtemp(prefix="pipguard-")
    register_temp_dir(tmp_dir)

    policy = load_policy(getattr(args, "policy", None))
    require_hashes = bool(args.require_hashes or policy.require_hashes)
    intel_feed = getattr(args, "intel_feed", None) or policy.intel_feed
    intel_enforce = bool(getattr(args, "enforce_intel", False) or policy.intel_enforce)

    packages: List[str] = args.packages or []
    requirements_file: Optional[str] = getattr(args, "r", None)
    extra_allow: List[str] = [*(policy.seed_allowlist or []), *(args.allow or [])]

    if not packages and not requirements_file:
        print("Error: specify package(s) or -r requirements.txt", file=sys.stderr)
        return 2

    if requirements_file:
        rc = _validate_requirements_file(
            requirements_file,
            require_hashes=require_hashes,
            allow_vcs_pinned=policy.allow_vcs_pinned,
            allow_direct_url_pinned=policy.allow_direct_url_pinned,
        )
        if rc != 0:
            return rc

    print(f"📦 Downloading to {tmp_dir} ...")
    try:
        archive_files, sdist_rejects = download_packages(
            packages,
            tmp_dir,
            allow_sdist=args.allow_sdist,
            requirements_file=requirements_file,
            require_hashes=require_hashes,
        )
    except RuntimeError as exc:
        print(f"Error: {exc}", file=sys.stderr)
        return 2

    if sdist_rejects:
        print(
            "\n❌ Scan blocked: the following packages are source distributions (sdist).\n"
            "   pip executes setup.py during metadata extraction — pipguard blocks this.\n",
            file=sys.stderr,
        )
        for name in sdist_rejects:
            print(f"   • {name}", file=sys.stderr)
        print(
            "\n   Use --allow-sdist to proceed "
            "(DANGER: sdist install EXECUTES arbitrary code — "
            "pipguard's AST scan does NOT prevent this).\n",
            file=sys.stderr,
        )
        return 2

    if not archive_files:
        print("No downloadable packages found.", file=sys.stderr)
        return 2

    if intel_enforce and intel_feed:
        blocked = load_intel_feed(intel_feed)
        intel_results: List[PackageScanResult] = []
        for arch in archive_files:
            name = _pkg_name_from_filename(arch).lower()
            version = _pkg_version_from_filename(arch)
            reason = blocked.get((name, version))
            if reason:
                intel_results.append(PackageScanResult(
                    package_name=f"{name}=={version}",
                    version=version,
                    findings=[Finding(
                        level=RiskLevel.CRITICAL,
                        file_path=arch,
                        line=0,
                        description=f"Intel feed blocked package: {reason}",
                    )],
                ))
        if intel_results:
            print_findings_report(intel_results)
            print("\n❌ Installation BLOCKED — package denied by threat-intel feed.", file=sys.stderr)
            return 1

    # Parallel scan (Architecture Amendment A8)
    n = len(archive_files)
    workers = min(n, os.cpu_count() or 4)
    print(f"🔍 Scanning {n} package(s) ...")

    results: List[PackageScanResult] = []
    with concurrent.futures.ThreadPoolExecutor(max_workers=workers) as pool:
        future_to_arch = {
            pool.submit(_scan_one_package, arch, tmp_dir, extra_allow): arch
            for arch in archive_files
        }
        for future in concurrent.futures.as_completed(future_to_arch):
            try:
                results.append(future.result())
            except Exception as exc:
                pkg = _pkg_name_from_filename(future_to_arch[future])
                print(f"Warning: scan failed for {pkg}: {exc}", file=sys.stderr)
                results.append(PackageScanResult(
                    package_name=pkg,
                    version="",
                    findings=[Finding(
                        level=RiskLevel.MEDIUM,
                        file_path=future_to_arch[future],
                        line=0,
                        description=f"Scan error (fail-safe): {exc}",
                    )],
                ))

    print_findings_report(results)

    # Determine worst effective risk level across all packages
    max_level = RiskLevel.CLEAN
    for r in results:
        if r.effective_level.value > max_level.value:
            max_level = r.effective_level

    # Gate logic
    if max_level in (RiskLevel.CRITICAL, RiskLevel.HIGH):
        if args.force:
            risky = [r.package_name for r in results
                     if r.effective_level in (RiskLevel.CRITICAL, RiskLevel.HIGH)]
            print(
                f"\n⚠️  WARNING: --force used. Installing despite {max_level} findings.\n"
                f"   Packages with findings: {', '.join(risky)}",
                file=sys.stderr,
            )
            # Fall through to install
        else:
            print(
                f"\n❌ Installation BLOCKED — {max_level} risk detected.\n"
                f"   Use --force to override (not recommended).",
                file=sys.stderr,
            )
            return 1

    elif max_level in (RiskLevel.MEDIUM, RiskLevel.LOW):
        if policy.binary_only == "block" and any(r.is_binary_only for r in results):
            print(
                "\n❌ Installation BLOCKED — policy binary_only=block and binary-only wheel detected.",
                file=sys.stderr,
            )
            return 1
        if args.yes:
            print(f"\n⚠️  {max_level} findings present. Proceeding because --yes was set.")
        elif not _confirm_install():
            print("Installation cancelled.", file=sys.stderr)
            return 1

    # Install from locally scanned files — NEVER re-download (TOCTOU fix, A2)
    print("\n⚙️  Installing from scanned local cache ...")
    rc = install_from_local(
        packages,
        tmp_dir,
        requirements_file=requirements_file,
        require_hashes=require_hashes,
    )
    if rc == 0:
        print("✅ Installation complete.")
    else:
        print(f"❌ pip install failed (exit {rc}).", file=sys.stderr)
        return 2
    return 0


# ── CLI wiring ───────────────────────────────────────────────────────────────

def build_parser() -> argparse.ArgumentParser:
    parser = argparse.ArgumentParser(
        prog="pipguard",
        description=(
            "Scan Python packages for supply chain attacks before installing.\n"
            "Zero config. Zero external dependencies. Pure stdlib."
        ),
        formatter_class=argparse.RawDescriptionHelpFormatter,
    )
    parser.add_argument("--version", action="version", version=f"pipguard {__version__}")

    sub = parser.add_subparsers(dest="command", required=True)

    install = sub.add_parser(
        "install",
        help="Download, scan, and install package(s) or a requirements file",
    )
    install.add_argument(
        "packages", nargs="*", metavar="package",
        help="Package(s) to install (e.g. requests>=2.28 or litellm==1.82.8)",
    )
    install.add_argument(
        "-r", metavar="requirements.txt",
        help="Requirements file to install from",
    )
    install.add_argument(
        "--yes", "-y", action="store_true",
        help="Skip confirmation prompts (still exits 1 on CRITICAL/HIGH)",
    )
    install.add_argument(
        "--force", action="store_true",
        help="Override even CRITICAL findings (escape hatch for known false-positives)",
    )
    install.add_argument(
        "--allow", action="append", metavar="package", default=[],
        help="Add package to per-invocation allowlist (repeatable)",
    )
    install.add_argument(
        "--allow-sdist", action="store_true",
        help=(
            "Allow sdist packages "
            "(DANGER: sdist install EXECUTES arbitrary code — "
            "pipguard's AST scan does NOT prevent this)"
        ),
    )
    install.add_argument(
        "--require-hashes", action="store_true",
        help="Require hashes for all requirements entries (also configurable in policy)",
    )
    install.add_argument(
        "--policy", metavar="pipguard.toml",
        help="Path to policy file (default: ./pipguard.toml if present)",
    )
    install.add_argument(
        "--intel-feed", metavar="FILE_OR_URL",
        help="Threat-intel JSON feed location with blocked package versions",
    )
    install.add_argument(
        "--enforce-intel", action="store_true",
        help="Block packages present in intel feed",
    )
    return parser


def main() -> int:
    """Entry point for the `pipguard` CLI."""
    parser = build_parser()
    args = parser.parse_args()
    if args.command == "install":
        return cmd_install(args)
    return 0  # pragma: no cover


if __name__ == "__main__":
    sys.exit(main())
