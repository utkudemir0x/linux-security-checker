"""Unit tests for scanner.report (scoring and rendering)."""

from __future__ import annotations

import json
import unittest

from scanner.report import SecurityReport
from scanner.utils import Finding, RiskLevel


def make_finding(risk: RiskLevel, category: str = "Test") -> Finding:
    return Finding(
        category=category,
        title=f"{risk.value} finding",
        description="Example description.",
        risk=risk,
    )


class TestScoring(unittest.TestCase):
    def test_perfect_score_with_no_findings(self) -> None:
        report = SecurityReport([])
        self.assertEqual(report.score(), 100)
        self.assertEqual(report.score_grade(), "Excellent")

    def test_score_decreases_with_findings(self) -> None:
        findings = [make_finding(RiskLevel.HIGH)]
        report = SecurityReport(findings)
        self.assertEqual(report.score(), 90)  # 100 - 10

    def test_score_never_goes_below_zero(self) -> None:
        findings = [make_finding(RiskLevel.CRITICAL) for _ in range(10)]
        report = SecurityReport(findings)
        self.assertEqual(report.score(), 0)

    def test_info_findings_do_not_affect_score(self) -> None:
        findings = [make_finding(RiskLevel.INFO) for _ in range(20)]
        report = SecurityReport(findings)
        self.assertEqual(report.score(), 100)

    def test_mixed_findings_score(self) -> None:
        findings = [
            make_finding(RiskLevel.CRITICAL),  # -25
            make_finding(RiskLevel.HIGH),      # -10
            make_finding(RiskLevel.MEDIUM),    # -5
            make_finding(RiskLevel.LOW),       # -2
            make_finding(RiskLevel.INFO),      # -0
        ]
        report = SecurityReport(findings)
        self.assertEqual(report.score(), 100 - 25 - 10 - 5 - 2)


class TestCountsByRisk(unittest.TestCase):
    def test_counts_are_accurate(self) -> None:
        findings = [
            make_finding(RiskLevel.HIGH),
            make_finding(RiskLevel.HIGH),
            make_finding(RiskLevel.LOW),
        ]
        report = SecurityReport(findings)
        counts = report.counts_by_risk()
        self.assertEqual(counts[RiskLevel.HIGH], 2)
        self.assertEqual(counts[RiskLevel.LOW], 1)
        self.assertEqual(counts[RiskLevel.CRITICAL], 0)


class TestGrouping(unittest.TestCase):
    def test_findings_grouped_by_category(self) -> None:
        findings = [
            make_finding(RiskLevel.INFO, category="SSH"),
            make_finding(RiskLevel.LOW, category="SSH"),
            make_finding(RiskLevel.MEDIUM, category="Firewall"),
        ]
        report = SecurityReport(findings)
        grouped = report.findings_by_category()
        self.assertEqual(set(grouped.keys()), {"SSH", "Firewall"})
        self.assertEqual(len(grouped["SSH"]), 2)
        self.assertEqual(len(grouped["Firewall"]), 1)


class TestJSONOutput(unittest.TestCase):
    def test_to_json_is_valid_and_complete(self) -> None:
        findings = [make_finding(RiskLevel.HIGH), make_finding(RiskLevel.INFO)]
        report = SecurityReport(findings, scan_errors=["SomeScanner failed: boom"])
        data = json.loads(report.to_json())

        self.assertEqual(data["security_score"], 90)
        self.assertEqual(data["total_findings"], 2)
        self.assertEqual(data["summary"]["HIGH"], 1)
        self.assertEqual(data["summary"]["INFO"], 1)
        self.assertEqual(data["scan_errors"], ["SomeScanner failed: boom"])
        self.assertEqual(len(data["findings"]), 2)
        self.assertEqual(data["findings"][0]["risk"], "HIGH")


if __name__ == "__main__":
    unittest.main()
