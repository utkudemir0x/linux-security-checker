"""Report aggregation, scoring, and output formatting.

Collects :class:`~scanner.utils.Finding` objects from every scanner,
computes an overall security score, and renders the result either as a
colorized terminal report or as machine-readable JSON.
"""

from __future__ import annotations

import json
from datetime import datetime, timezone

from scanner.utils import ANSI_BOLD, ANSI_CYAN, ANSI_DIM, ANSI_RESET, Finding, RiskLevel

MAX_SCORE = 100
MIN_SCORE = 0


class SecurityReport:
    """Aggregates findings from all scanners into a single report."""

    def __init__(self, findings: list[Finding], scan_errors: list[str] | None = None) -> None:
        self.findings = findings
        self.scan_errors = scan_errors or []
        self.generated_at = datetime.now(timezone.utc)

    def counts_by_risk(self) -> dict[RiskLevel, int]:
        """Return the number of findings for each risk level."""
        counts = {level: 0 for level in RiskLevel}
        for finding in self.findings:
            counts[finding.risk] += 1
        return counts

    def score(self) -> int:
        """Compute an overall 0-100 security score.

        Starts at 100 and subtracts a weighted penalty per finding based
        on its risk level (see :attr:`RiskLevel.weight`). The result is
        clamped to the ``[0, 100]`` range.
        """
        penalty = sum(finding.risk.weight for finding in self.findings)
        return max(MIN_SCORE, min(MAX_SCORE, MAX_SCORE - penalty))

    def score_grade(self) -> str:
        """Return a letter-style grade label for the current score."""
        score = self.score()
        if score >= 90:
            return "Excellent"
        if score >= 75:
            return "Good"
        if score >= 50:
            return "Needs Improvement"
        return "Critical Attention Required"

    def findings_by_category(self) -> dict[str, list[Finding]]:
        """Group findings by their scanner category, preserving order."""
        grouped: dict[str, list[Finding]] = {}
        for finding in self.findings:
            grouped.setdefault(finding.category, []).append(finding)
        return grouped

    # ------------------------------------------------------------------
    # Output renderers
    # ------------------------------------------------------------------

    def to_dict(self) -> dict:
        """Serialize the full report to a JSON-friendly dictionary."""
        counts = self.counts_by_risk()
        return {
            "generated_at": self.generated_at.isoformat(),
            "security_score": self.score(),
            "grade": self.score_grade(),
            "summary": {level.value: counts[level] for level in RiskLevel},
            "total_findings": len(self.findings),
            "scan_errors": self.scan_errors,
            "findings": [finding.to_dict() for finding in self.findings],
        }

    def to_json(self, indent: int = 2) -> str:
        """Serialize the report to a JSON string."""
        return json.dumps(self.to_dict(), indent=indent, ensure_ascii=False)

    def print_terminal(self) -> None:
        """Print a colorized, human-friendly report to the terminal."""
        self._print_header()
        for category, findings in self.findings_by_category().items():
            self._print_category(category, findings)
        self._print_summary()
        if self.scan_errors:
            self._print_scan_errors()

    def _print_header(self) -> None:
        title = " Linux Security Checker - Scan Report "
        print(f"\n{ANSI_BOLD}{ANSI_CYAN}{title.center(70, '=')}{ANSI_RESET}")
        timestamp = self.generated_at.strftime("%Y-%m-%d %H:%M:%S UTC")
        print(f"{ANSI_DIM}Generated at: {timestamp}{ANSI_RESET}\n")

    def _print_category(self, category: str, findings: list[Finding]) -> None:
        print(f"{ANSI_BOLD}## {category}{ANSI_RESET}")
        for finding in findings:
            color = finding.risk.ansi_color
            emoji = finding.risk.emoji
            print(f"  {emoji} {color}[{finding.risk.value:<8}]{ANSI_RESET} {finding.title}")
            print(f"           {finding.description}")
            if finding.recommendation:
                print(f"           {ANSI_DIM}→ Recommendation: {finding.recommendation}{ANSI_RESET}")
        print()

    def _print_summary(self) -> None:
        counts = self.counts_by_risk()
        score = self.score()
        grade = self.score_grade()

        print(f"{ANSI_BOLD}{'-' * 70}{ANSI_RESET}")
        print(f"{ANSI_BOLD}Security Score: {score}/100  ({grade}){ANSI_RESET}\n")
        print(f"  {RiskLevel.CRITICAL.emoji} Critical : {counts[RiskLevel.CRITICAL]}")
        print(f"  {RiskLevel.HIGH.emoji} High     : {counts[RiskLevel.HIGH]}")
        print(f"  {RiskLevel.MEDIUM.emoji} Medium   : {counts[RiskLevel.MEDIUM]}")
        print(f"  {RiskLevel.LOW.emoji} Low      : {counts[RiskLevel.LOW]}")
        print(f"  {RiskLevel.INFO.emoji} Info     : {counts[RiskLevel.INFO]}")
        print(f"{ANSI_BOLD}{'-' * 70}{ANSI_RESET}\n")

    def _print_scan_errors(self) -> None:
        print(f"{ANSI_BOLD}Scanner warnings:{ANSI_RESET}")
        for error in self.scan_errors:
            print(f"  - {error}")
        print()
