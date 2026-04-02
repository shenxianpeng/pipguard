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
import sys
import tempfile
from typing import List, Optional

from . import __version__
from .aggregator import aggregate_findings, check_package_name_for_homoglyph, print_findings_report
from .cleanup import install_signal_handlers, register_temp_dir
from .downloader import download_packages
from .extractor import collect_binary_extension_files, collect_scannable_files, extract_archive
from .installer import install_from_local
from .models import Finding, PackageScanResult, RiskLevel
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

def _validate_requirements_file(filepath: str) -> int:
    """
    Validate requirements.txt for unsupported formats (Phase 1).
    Returns 0 if OK, 2 if unsupported entries are found.
    """
    unsupported = []
    try:
        with open(filepath, "r", encoding="utf-8") as f:
            for lineno, raw in enumerate(f, 1):
                line = raw.strip()
                if not line or line.startswith("#") or line.startswith("--"):
                    continue
                if line.startswith("-e "):
                    print(
                        f"  Note: skipping editable install at line {lineno}: {line}",
                        file=sys.stderr,
                    )
                    continue
                if any(
                    line.startswith(prefix)
                    for prefix in ("git+", "hg+", "svn+", "bzr+")
                ):
                    unsupported.append((lineno, line, "VCS dependency"))
                elif " @ " in line:
                    # PEP 508 direct URL: pkg @ https://... or pkg @ file:///...
                    unsupported.append((lineno, line, "direct URL dependency (PEP 508 @ syntax)"))
                elif line.startswith("./") or line.startswith("../") or (
                    line.startswith("/") and not line.startswith("-")
                ):
                    unsupported.append((lineno, line, "local path dependency"))
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
            "\n  Supported: PyPI specifiers, version pins, hash-locked deps.\n"
            "  Not supported: VCS deps (git+...), local paths (./...).",
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

    packages: List[str] = args.packages or []
    requirements_file: Optional[str] = getattr(args, "r", None)
    extra_allow: List[str] = args.allow or []

    if not packages and not requirements_file:
        print("Error: specify package(s) or -r requirements.txt", file=sys.stderr)
        return 2

    if requirements_file:
        rc = _validate_requirements_file(requirements_file)
        if rc != 0:
            return rc

    print(f"📦 Downloading to {tmp_dir} ...")
    try:
        archive_files, sdist_rejects = download_packages(
            packages,
            tmp_dir,
            allow_sdist=args.allow_sdist,
            requirements_file=requirements_file,
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
        if args.yes:
            print(f"\n⚠️  {max_level} findings present. Proceeding because --yes was set.")
        elif not _confirm_install():
            print("Installation cancelled.", file=sys.stderr)
            return 1

    # Install from locally scanned files — NEVER re-download (TOCTOU fix, A2)
    print("\n⚙️  Installing from scanned local cache ...")
    rc = install_from_local(packages, tmp_dir, requirements_file=requirements_file)
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
