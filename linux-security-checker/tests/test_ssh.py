"""Unit tests for scanner.ssh (sshd_config parsing and risk evaluation)."""

from __future__ import annotations

import tempfile
import unittest
from pathlib import Path

from scanner.ssh import SSHSecurityScanner
from scanner.utils import RiskLevel

INSECURE_CONFIG = """
# Example insecure sshd_config
PermitRootLogin yes
PasswordAuthentication yes
Port 22
PubkeyAuthentication yes
MaxAuthTries 10
"""

HARDENED_CONFIG = """
PermitRootLogin no
PasswordAuthentication no
Port 2222
AllowUsers deploy
PubkeyAuthentication yes
MaxAuthTries 3
"""


class TestSSHSecurityScanner(unittest.TestCase):
    def setUp(self) -> None:
        self._tmp_dir = tempfile.TemporaryDirectory()
        self.tmp_path = Path(self._tmp_dir.name)

    def tearDown(self) -> None:
        self._tmp_dir.cleanup()

    def _write_config(self, content: str) -> str:
        path = self.tmp_path / "sshd_config"
        path.write_text(content)
        return str(path)

    def test_missing_config_reports_info_only(self) -> None:
        scanner = SSHSecurityScanner(config_path=str(self.tmp_path / "nope"))
        findings = scanner.scan()
        self.assertEqual(len(findings), 1)
        self.assertEqual(findings[0].risk, RiskLevel.INFO)

    def test_insecure_config_flags_high_and_medium_risks(self) -> None:
        config_path = self._write_config(INSECURE_CONFIG)
        scanner = SSHSecurityScanner(config_path=config_path)
        findings = {f.title: f for f in scanner.scan()}

        self.assertEqual(findings["PermitRootLogin"].risk, RiskLevel.HIGH)
        self.assertEqual(findings["PasswordAuthentication"].risk, RiskLevel.MEDIUM)
        self.assertEqual(findings["SSH Port"].risk, RiskLevel.LOW)
        self.assertEqual(findings["MaxAuthTries"].risk, RiskLevel.LOW)

    def test_hardened_config_is_mostly_info(self) -> None:
        config_path = self._write_config(HARDENED_CONFIG)
        scanner = SSHSecurityScanner(config_path=config_path)
        findings = {f.title: f for f in scanner.scan()}

        self.assertEqual(findings["PermitRootLogin"].risk, RiskLevel.INFO)
        self.assertEqual(findings["PasswordAuthentication"].risk, RiskLevel.INFO)
        self.assertEqual(findings["SSH Port"].risk, RiskLevel.INFO)
        self.assertEqual(findings["AllowUsers / AllowGroups"].risk, RiskLevel.INFO)
        self.assertEqual(findings["MaxAuthTries"].risk, RiskLevel.INFO)

    def test_first_directive_occurrence_wins(self) -> None:
        config_path = self._write_config("PermitRootLogin no\nPermitRootLogin yes\n")
        scanner = SSHSecurityScanner(config_path=config_path)
        findings = {f.title: f for f in scanner.scan()}
        self.assertEqual(findings["PermitRootLogin"].risk, RiskLevel.INFO)


if __name__ == "__main__":
    unittest.main()
