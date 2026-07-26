
from __future__ import annotations

from scanner.utils import Finding, RiskLevel, command_exists, read_file_safe, run_command

SENSITIVE_MOUNTS = {"/tmp", "/var/tmp", "/dev/shm"}


class FileSystemScanner:
    """Scans mounted filesystems, swap and disk encryption status."""

    category = "Filesystem"

    def scan(self) -> list[Finding]:
        """Run all filesystem checks and return the findings."""
        findings: list[Finding] = []
        findings.extend(self._check_mount_options())
        findings.extend(self._check_luks_encryption())
        findings.extend(self._check_swap())
        return findings

    def _check_mount_options(self) -> list[Finding]:
        findings: list[Finding] = []
        content = read_file_safe("/proc/mounts")
        if not content:
            return findings

        already_checked: set[str] = set()
        for line in content.splitlines():
            parts = line.split()
            if len(parts) < 4:
                continue
            _device, mount_point, _fstype, options = parts[0], parts[1], parts[2], parts[3]
            if mount_point not in SENSITIVE_MOUNTS or mount_point in already_checked:
                continue
            already_checked.add(mount_point)

            opts = set(options.split(","))
            missing = {"nosuid", "nodev"} - opts
            if missing:
                findings.append(
                    Finding(
                        category=self.category,
                        title=f"{mount_point} missing hardening mount options",
                        description=(
                            f"{mount_point} is mounted without: {', '.join(sorted(missing))}. "
                            "This can allow SUID binaries or device files to be used from a "
                            "world-writable location."
                        ),
                        risk=RiskLevel.MEDIUM,
                        recommendation=(
                            f"Add {'/'.join(sorted(missing))} to the mount options for "
                            f"{mount_point} in /etc/fstab."
                        ),
                    )
                )
            else:
                findings.append(
                    Finding(
                        category=self.category,
                        title=f"{mount_point} mount options",
                        description=f"{mount_point} is properly hardened ({options}).",
                        risk=RiskLevel.INFO,
                    )
                )
        return findings

    def _check_luks_encryption(self) -> list[Finding]:
        findings: list[Finding] = []
        if not command_exists("lsblk"):
            findings.append(
                Finding(
                    category=self.category,
                    title="Disk encryption check skipped",
                    description="'lsblk' is not available; could not determine LUKS status.",
                    risk=RiskLevel.INFO,
                )
            )
            return findings

        result = run_command(["lsblk", "-o", "NAME,TYPE,FSTYPE", "-n"])
        if not result.ok:
            return findings

        has_luks = any("crypto_luks" in line.lower() for line in result.stdout.splitlines())
        if has_luks:
            findings.append(
                Finding(
                    category=self.category,
                    title="Disk encryption (LUKS)",
                    description="At least one LUKS-encrypted block device was detected.",
                    risk=RiskLevel.INFO,
                )
            )
        else:
            findings.append(
                Finding(
                    category=self.category,
                    title="Disk encryption (LUKS)",
                    description="No LUKS-encrypted block devices were detected.",
                    risk=RiskLevel.LOW,
                    recommendation=(
                        "Consider full-disk encryption (LUKS) to protect data at rest, "
                        "especially on laptops or removable media."
                    ),
                )
            )
        return findings

    def _check_swap(self) -> list[Finding]:
        findings: list[Finding] = []
        content = read_file_safe("/proc/swaps")
        if content is None:
            return findings

        lines = [ln for ln in content.splitlines()[1:] if ln.strip()]
        if lines:
            findings.append(
                Finding(
                    category=self.category,
                    title="Swap configuration",
                    description=f"{len(lines)} active swap device(s)/file(s) found.",
                    risk=RiskLevel.INFO,
                    recommendation=(
                        "If the root filesystem is encrypted, ensure swap is encrypted too, "
                        "otherwise sensitive memory contents may be written to disk in the clear."
                    ),
                )
            )
        else:
            findings.append(
                Finding(
                    category=self.category,
                    title="Swap configuration",
                    description="No active swap devices found.",
                    risk=RiskLevel.INFO,
                )
            )
        return findings
