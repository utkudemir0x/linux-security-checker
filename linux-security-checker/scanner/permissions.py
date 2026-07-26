"""File permission scanner.

Searches common filesystem locations for SUID and SGID binaries,
world-writable files, and files with permissive ``777`` modes, plus
sanity-checks the permissions of a few critical system files.
"""

from __future__ import annotations

from scanner.utils import Finding, RiskLevel, command_exists, run_command

# Restrict searches to real filesystems to keep scans fast and to avoid
# noisy/irrelevant results from proc, sys, and other pseudo filesystems.
SEARCH_PATHS = ["/bin", "/sbin", "/usr", "/etc", "/opt", "/home", "/root"]
EXCLUDED_PATHS = ["/proc", "/sys", "/run", "/dev"]

# A small allow-list of SUID binaries that are expected on most distros,
# to reduce noise; anything outside this list is still reported but the
# overall finding highlights unusual entries separately.
COMMON_SUID_BINARIES = {
    "su", "sudo", "passwd", "mount", "umount", "ping", "ping6",
    "chsh", "chfn", "gpasswd", "newgrp", "pkexec", "fusermount",
    "fusermount3", "mount.nfs", "sudoedit", "unix_chkpwd",
}

MAX_LISTED_ITEMS = 15
SEARCH_TIMEOUT_SECONDS = 30


class PermissionsScanner:
    """Scans for SUID/SGID binaries and world-writable / 777 files."""

    category = "Permissions"

    def scan(self) -> list[Finding]:
        """Run all permission checks and return the findings."""
        findings: list[Finding] = []
        findings.extend(self._check_suid_files())
        findings.extend(self._check_sgid_files())
        findings.extend(self._check_world_writable_files())
        findings.extend(self._check_777_files())
        findings.extend(self._check_critical_file_permissions())
        return findings

    def _find(self, args: list[str]) -> list[str]:
        """Run `find` with the given trailing args across SEARCH_PATHS."""
        if not command_exists("find"):
            return []
        cmd = ["find", *SEARCH_PATHS, "-xdev", *args]
        result = run_command(cmd, timeout=SEARCH_TIMEOUT_SECONDS)
        if not result.ok:
            return []
        return [line for line in result.stdout.splitlines() if line.strip()]

    def _check_suid_files(self) -> list[Finding]:
        paths = self._find(["-perm", "-4000", "-type", "f"])
        unusual = [p for p in paths if p.rsplit("/", 1)[-1] not in COMMON_SUID_BINARIES]

        risk = RiskLevel.MEDIUM if unusual else RiskLevel.INFO
        description = f"Found {len(paths)} SUID binaries."
        if unusual:
            shown = unusual[:MAX_LISTED_ITEMS]
            description += (
                f" {len(unusual)} of them are outside the common allow-list: "
                + ", ".join(shown)
                + (f" (+{len(unusual) - MAX_LISTED_ITEMS} more)" if len(unusual) > MAX_LISTED_ITEMS else "")
            )
        return [
            Finding(
                category=self.category,
                title="SUID binaries",
                description=description,
                risk=risk,
                recommendation=(
                    "Review unusual SUID binaries; remove the SUID bit "
                    "(`chmod u-s <file>`) if not required."
                    if unusual
                    else ""
                ),
            )
        ]

    def _check_sgid_files(self) -> list[Finding]:
        paths = self._find(["-perm", "-2000", "-type", "f"])
        shown = paths[:MAX_LISTED_ITEMS]
        description = f"Found {len(paths)} SGID binaries."
        if shown:
            description += ": " + ", ".join(shown)
            if len(paths) > MAX_LISTED_ITEMS:
                description += f" (+{len(paths) - MAX_LISTED_ITEMS} more)"
        return [
            Finding(
                category=self.category,
                title="SGID binaries",
                description=description,
                risk=RiskLevel.INFO if len(paths) < 20 else RiskLevel.LOW,
                recommendation="Audit SGID binaries periodically for unexpected additions.",
            )
        ]

    def _check_world_writable_files(self) -> list[Finding]:
        paths = self._find(["-perm", "-0002", "-type", "f", "-not", "-path", "*/proc/*"])
        # Exclude typical intentionally-writable spots to reduce noise.
        filtered = [p for p in paths if not p.startswith(("/tmp", "/var/tmp", "/dev/shm"))]

        risk = RiskLevel.HIGH if filtered else RiskLevel.INFO
        shown = filtered[:MAX_LISTED_ITEMS]
        description = f"Found {len(filtered)} world-writable file(s) outside of temp directories."
        if shown:
            description += ": " + ", ".join(shown)
            if len(filtered) > MAX_LISTED_ITEMS:
                description += f" (+{len(filtered) - MAX_LISTED_ITEMS} more)"

        return [
            Finding(
                category=self.category,
                title="World-writable files",
                description=description,
                risk=risk,
                recommendation=(
                    "Remove world-write permission (`chmod o-w <file>`) unless intentional."
                    if filtered
                    else ""
                ),
            )
        ]

    def _check_777_files(self) -> list[Finding]:
        paths = self._find(["-perm", "0777", "-type", "f"])
        risk = RiskLevel.HIGH if paths else RiskLevel.INFO
        shown = paths[:MAX_LISTED_ITEMS]
        description = f"Found {len(paths)} file(s) with permissive 777 permissions."
        if shown:
            description += ": " + ", ".join(shown)
            if len(paths) > MAX_LISTED_ITEMS:
                description += f" (+{len(paths) - MAX_LISTED_ITEMS} more)"

        return [
            Finding(
                category=self.category,
                title="777-permission files",
                description=description,
                risk=risk,
                recommendation=(
                    "Apply least-privilege permissions (e.g. `chmod 644` or `755` as appropriate)."
                    if paths
                    else ""
                ),
            )
        ]

    def _check_critical_file_permissions(self) -> list[Finding]:
        """Sanity-check permissions of a few security-critical files."""
        findings: list[Finding] = []
        critical_files = {
            "/etc/shadow": "0640",
            "/etc/passwd": "0644",
            "/etc/gshadow": "0640",
        }

        for path, expected_max in critical_files.items():
            result = run_command(["stat", "-c", "%a", path])
            if not result.ok or result.returncode != 0 or not result.stdout:
                continue
            actual = result.stdout.strip()
            try:
                is_too_permissive = int(actual, 8) > int(expected_max, 8)
            except ValueError:
                is_too_permissive = False

            if is_too_permissive:
                findings.append(
                    Finding(
                        category=self.category,
                        title=f"Loose permissions on {path}",
                        description=f"{path} has mode {actual}, more permissive than the "
                        f"recommended {expected_max}.",
                        risk=RiskLevel.HIGH,
                        recommendation=f"Run `chmod {expected_max} {path}`.",
                    )
                )
            else:
                findings.append(
                    Finding(
                        category=self.category,
                        title=f"Permissions on {path}",
                        description=f"{path} has mode {actual}, within expected bounds.",
                        risk=RiskLevel.INFO,
                    )
                )
        return findings
