"""Shared utilities, data models and helper functions.

This module defines the core data model (:class:`RiskLevel`,
:class:`Finding`) used by every scanner, along with small, defensive
helper functions for running shell commands, reading files safely and
detecting the host Linux distribution. All helpers are designed to
fail *softly*: a missing binary, a permission error or a timeout never
raises an unhandled exception up to the caller, they simply return
``None`` / empty results so a single unavailable tool cannot crash the
whole scan.
"""

from __future__ import annotations

import os
import shutil
import subprocess
from dataclasses import dataclass, field
from enum import Enum
from typing import Optional


class RiskLevel(Enum):
    """Severity levels used to classify every finding produced by a scan."""

    INFO = "INFO"
    LOW = "LOW"
    MEDIUM = "MEDIUM"
    HIGH = "HIGH"
    CRITICAL = "CRITICAL"

    @property
    def weight(self) -> int:
        """Return the score penalty associated with this risk level."""
        return {
            RiskLevel.INFO: 0,
            RiskLevel.LOW: 2,
            RiskLevel.MEDIUM: 5,
            RiskLevel.HIGH: 10,
            RiskLevel.CRITICAL: 25,
        }[self]

    @property
    def emoji(self) -> str:
        """Return the emoji used in terminal output for this level."""
        return {
            RiskLevel.INFO: "🟢",
            RiskLevel.LOW: "🟡",
            RiskLevel.MEDIUM: "🟠",
            RiskLevel.HIGH: "🔴",
            RiskLevel.CRITICAL: "❌",
        }[self]

    @property
    def ansi_color(self) -> str:
        """Return the ANSI escape code used to colorize this level."""
        return {
            RiskLevel.INFO: "\033[92m",       # green
            RiskLevel.LOW: "\033[93m",        # yellow
            RiskLevel.MEDIUM: "\033[38;5;208m",  # orange
            RiskLevel.HIGH: "\033[91m",       # red
            RiskLevel.CRITICAL: "\033[1;97;41m",  # bold white on red
        }[self]


ANSI_RESET = "\033[0m"
ANSI_BOLD = "\033[1m"
ANSI_DIM = "\033[2m"
ANSI_CYAN = "\033[96m"


@dataclass
class Finding:
    """A single security observation produced by a scanner.

    Attributes:
        category: Human readable name of the scanner/category that
            produced the finding (e.g. ``"SSH"``, ``"Users"``).
        title: Short one-line summary of the finding.
        description: Longer, detailed explanation of what was found.
        risk: The :class:`RiskLevel` severity of the finding.
        recommendation: Optional actionable remediation advice.
    """

    category: str
    title: str
    description: str
    risk: RiskLevel
    recommendation: str = ""

    def to_dict(self) -> dict:
        """Serialize the finding to a JSON-friendly dictionary."""
        return {
            "category": self.category,
            "title": self.title,
            "description": self.description,
            "risk": self.risk.value,
            "recommendation": self.recommendation,
        }


@dataclass
class CommandResult:
    """Result of running an external command via :func:`run_command`."""

    ok: bool
    stdout: str = ""
    stderr: str = ""
    returncode: Optional[int] = None
    error: str = field(default="")


def command_exists(name: str) -> bool:
    """Return True if an executable named ``name`` exists on PATH."""
    return shutil.which(name) is not None


def run_command(cmd: list[str], timeout: int = 5) -> CommandResult:
    """Run a command safely, never raising on failure.

    Args:
        cmd: The command and its arguments as a list of strings.
        timeout: Maximum number of seconds to wait before giving up.

    Returns:
        A :class:`CommandResult` describing the outcome. ``ok`` is
        ``False`` if the binary is missing, the command timed out, or
        any other OS-level error occurred; it does NOT reflect the
        command's exit code (callers should check ``returncode``
        themselves when relevant, e.g. ``systemctl is-active`` returns
        non-zero for inactive services, which is a valid result).
    """
    if not cmd:
        return CommandResult(ok=False, error="empty command")
    if not command_exists(cmd[0]):
        return CommandResult(ok=False, error=f"'{cmd[0]}' not found on PATH")
    try:
        proc = subprocess.run(
            cmd,
            capture_output=True,
            text=True,
            timeout=timeout,
            check=False,
        )
        return CommandResult(
            ok=True,
            stdout=proc.stdout.strip(),
            stderr=proc.stderr.strip(),
            returncode=proc.returncode,
        )
    except subprocess.TimeoutExpired:
        return CommandResult(ok=False, error=f"command timed out after {timeout}s")
    except (OSError, ValueError) as exc:
        return CommandResult(ok=False, error=str(exc))


def read_file_safe(path: str) -> Optional[str]:
    """Read a text file and return its content, or None on any failure.

    Handles missing files, permission errors (e.g. non-root user trying
    to read ``/etc/shadow``) and decoding errors gracefully.
    """
    try:
        with open(path, "r", encoding="utf-8", errors="replace") as handle:
            return handle.read()
    except (FileNotFoundError, PermissionError, IsADirectoryError, OSError):
        return None


def is_root() -> bool:
    """Return True if the current process is running as root (uid 0)."""
    try:
        return os.geteuid() == 0
    except AttributeError:
        # os.geteuid() is not available on non-POSIX platforms.
        return False


def get_distro_info() -> dict[str, str]:
    """Parse ``/etc/os-release`` and return distro metadata.

    Returns a dict with keys such as ``name``, ``id``, ``version`` when
    available; falls back to ``{"name": "Unknown"}`` if the file is
    missing or unreadable.
    """
    content = read_file_safe("/etc/os-release")
    if not content:
        return {"name": "Unknown", "id": "unknown", "version": "unknown"}

    data: dict[str, str] = {}
    for line in content.splitlines():
        line = line.strip()
        if not line or "=" not in line:
            continue
        key, _, value = line.partition("=")
        data[key.strip().lower()] = value.strip().strip('"')

    return {
        "name": data.get("pretty_name", data.get("name", "Unknown")),
        "id": data.get("id", "unknown"),
        "version": data.get("version_id", data.get("version", "unknown")),
    }


SUPPORTED_DISTRO_IDS = {
    "ubuntu",
    "debian",
    "kali",
    "arch",
    "fedora",
    "centos",
    "rocky",
}


def is_supported_distro(distro_id: str) -> bool:
    """Return True if the given ``/etc/os-release`` ID is supported."""
    return distro_id.lower() in SUPPORTED_DISTRO_IDS


def bytes_to_human(num_bytes: float) -> str:
    """Convert a byte count into a human readable string (e.g. '1.5 GB')."""
    value = float(num_bytes)
    for unit in ("B", "KB", "MB", "GB", "TB", "PB"):
        if value < 1024.0:
            return f"{value:.1f} {unit}"
        value /= 1024.0
    return f"{value:.1f} EB"


def seconds_to_uptime(seconds: float) -> str:
    """Convert a number of seconds into a human readable uptime string."""
    seconds = int(seconds)
    days, seconds = divmod(seconds, 86400)
    hours, seconds = divmod(seconds, 3600)
    minutes, _ = divmod(seconds, 60)
    parts = []
    if days:
        parts.append(f"{days}d")
    if hours or days:
        parts.append(f"{hours}h")
    parts.append(f"{minutes}m")
    return " ".join(parts)
