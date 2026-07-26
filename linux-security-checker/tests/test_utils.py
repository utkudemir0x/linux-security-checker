

from __future__ import annotations

import tempfile
import unittest
from pathlib import Path

from scanner.utils import (
    Finding,
    RiskLevel,
    bytes_to_human,
    command_exists,
    get_distro_info,
    is_supported_distro,
    read_file_safe,
    run_command,
    seconds_to_uptime,
)


class TestRiskLevel(unittest.TestCase):
    def test_weight_ordering(self) -> None:
        self.assertEqual(RiskLevel.INFO.weight, 0)
        self.assertLess(RiskLevel.LOW.weight, RiskLevel.MEDIUM.weight)
        self.assertLess(RiskLevel.MEDIUM.weight, RiskLevel.HIGH.weight)
        self.assertLess(RiskLevel.HIGH.weight, RiskLevel.CRITICAL.weight)

    def test_all_levels_have_emoji_and_color(self) -> None:
        for level in RiskLevel:
            self.assertTrue(level.emoji)
            self.assertTrue(level.ansi_color.startswith("\033["))


class TestFinding(unittest.TestCase):
    def test_to_dict_roundtrip(self) -> None:
        finding = Finding(
            category="Test",
            title="Example",
            description="An example finding.",
            risk=RiskLevel.HIGH,
            recommendation="Fix it.",
        )
        self.assertEqual(
            finding.to_dict(),
            {
                "category": "Test",
                "title": "Example",
                "description": "An example finding.",
                "risk": "HIGH",
                "recommendation": "Fix it.",
            },
        )


class TestRunCommand(unittest.TestCase):
    def test_missing_binary_returns_not_ok(self) -> None:
        result = run_command(["this-binary-does-not-exist-12345"])
        self.assertFalse(result.ok)
        self.assertIn("not found", result.error)

    def test_empty_command_returns_not_ok(self) -> None:
        result = run_command([])
        self.assertFalse(result.ok)

    def test_existing_binary_runs(self) -> None:
        result = run_command(["echo", "hello"])
        self.assertTrue(result.ok)
        self.assertEqual(result.stdout, "hello")
        self.assertEqual(result.returncode, 0)


class TestReadFileSafe(unittest.TestCase):
    def test_missing_file_returns_none(self) -> None:
        self.assertIsNone(read_file_safe("/this/path/does/not/exist"))

    def test_existing_file_returns_content(self) -> None:
        with tempfile.TemporaryDirectory() as tmp_dir:
            file_path = Path(tmp_dir) / "sample.txt"
            file_path.write_text("hello world")
            self.assertEqual(read_file_safe(str(file_path)), "hello world")


class TestCommandExists(unittest.TestCase):
    def test_true_for_common_binary(self) -> None:
        self.assertTrue(command_exists("echo"))

    def test_false_for_bogus_binary(self) -> None:
        self.assertFalse(command_exists("definitely-not-a-real-command-xyz"))


class TestDistroHelpers(unittest.TestCase):
    def test_get_distro_info_returns_dict_with_expected_keys(self) -> None:
        info = get_distro_info()
        self.assertIn("name", info)
        self.assertIn("id", info)
        self.assertIn("version", info)

    def test_is_supported_distro(self) -> None:
        self.assertTrue(is_supported_distro("ubuntu"))
        self.assertTrue(is_supported_distro("UBUNTU"))
        self.assertFalse(is_supported_distro("gentoo"))


class TestHumanReadableHelpers(unittest.TestCase):
    def test_bytes_to_human(self) -> None:
        self.assertEqual(bytes_to_human(500), "500.0 B")
        self.assertEqual(bytes_to_human(1024), "1.0 KB")
        self.assertEqual(bytes_to_human(1024 * 1024), "1.0 MB")

    def test_seconds_to_uptime(self) -> None:
        self.assertEqual(seconds_to_uptime(60), "1m")
        self.assertEqual(seconds_to_uptime(3661), "1h 1m")
        self.assertEqual(seconds_to_uptime(90000), "1d 1h 0m")


if __name__ == "__main__":
    unittest.main()
