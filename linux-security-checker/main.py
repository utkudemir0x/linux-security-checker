#!/usr/bin/env python3
"""Linux Security Checker - CLI entry point.
Usage:
    python main.py scan
    python main.py scan --json
    python main.py scan --json --output report.json
"""

from __future__ import annotations

import argparse
import sys
from typing import Type

from scanner.filesystem import FileSystemScanner
from scanner.firewall import FirewallScanner
from scanner.kernel import SystemInfoScanner
from scanner.network import NetworkScanner
from scanner.packages import PackageScanner
from scanner.permissions import PermissionsScanner
from scanner.report import SecurityReport
from scanner.security import SecurityFeaturesScanner
from scanner.services import ServiceScanner
from scanner.ssh import SSHSecurityScanner
from scanner.users import UserSecurityScanner
from scanner.utils import Finding, RiskLevel, is_root


SCANNER_CLASSES: list[Type] = [
    SystemInfoScanner,
    UserSecurityScanner,
    SSHSecurityScanner,
    FirewallScanner,
    NetworkScanner,
    FileSystemScanner,
    PermissionsScanner,
    PackageScanner,
    SecurityFeaturesScanner,
    ServiceScanner,
]


def run_all_scanners() -> tuple[list[Finding], list[str]]:
    """Instantiate and run every scanner, isolating failures.

    Returns:
        A tuple of (all findings collected, list of scanner error
        messages). A single scanner raising an unexpected exception
        will not abort the rest of the scan; it is recorded as a
        warning instead.
    """
    findings: list[Finding] = []
    errors: list[str] = []

    for scanner_cls in SCANNER_CLASSES:
        try:
            scanner = scanner_cls()
            findings.extend(scanner.scan())
        except Exception as exc:  
            errors.append(f"{scanner_cls.__name__} failed: {exc}")

    return findings, errors


def build_arg_parser() -> argparse.ArgumentParser:
    """Build the top-level CLI argument parser."""
    parser = argparse.ArgumentParser(
        prog="linux-security-checker",
        description="Defensive Linux security auditing CLI tool.",
    )
    subparsers = parser.add_subparsers(dest="command", required=True)

    scan_parser = subparsers.add_parser("scan", help="Run a full security scan.")
    scan_parser.add_argument(
        "--json",
        action="store_true",
        help="Output the report as JSON instead of a colorized terminal report.",
    )
    scan_parser.add_argument(
        "--output",
        metavar="FILE",
        help="Write the report to FILE instead of stdout (works with or without --json).",
    )
    scan_parser.add_argument(
        "--min-severity",
        choices=[level.value for level in RiskLevel],
        default=RiskLevel.INFO.value,
        help=(
            "Only include findings at or above this severity (default: INFO, i.e. all). "
            "Note: this also affects the computed security score, since it is based on "
            "whichever findings are included."
        ),
    )

    return parser


def filter_by_severity(findings: list[Finding], min_severity: str) -> list[Finding]:
    """Filter findings to those at or above the given minimum severity."""
    order = list(RiskLevel)
    min_index = order.index(RiskLevel(min_severity))
    return [f for f in findings if order.index(f.risk) >= min_index]


def main(argv: list[str] | None = None) -> int:
    """CLI entry point. Returns a process exit code."""
    parser = build_arg_parser()
    args = parser.parse_args(argv)

    if args.command == "scan":
        if not is_root():
            print(
                "Note: not running as root - some checks (e.g. /etc/shadow analysis) "
                "will be limited. Re-run with sudo for a complete audit.\n",
                file=sys.stderr,
            )

        findings, errors = run_all_scanners()
        findings = filter_by_severity(findings, args.min_severity)
        report = SecurityReport(findings, scan_errors=errors)

        if args.json:
            output = report.to_json()
        else:
            output = None  

        if args.output:
            with open(args.output, "w", encoding="utf-8") as handle:
                if args.json:
                    handle.write(output or "")
                else:
                    
                    import contextlib
                    import io

                    buffer = io.StringIO()
                    with contextlib.redirect_stdout(buffer):
                        report.print_terminal()
                    handle.write(buffer.getvalue())
            print(f"Report written to {args.output}")
        else:
            if args.json:
                print(output)
            else:
                report.print_terminal()

        
        if any(f.risk == RiskLevel.CRITICAL for f in findings):
            return 2
        return 0

    parser.print_help()
    return 1


if __name__ == "__main__":
    sys.exit(main())
