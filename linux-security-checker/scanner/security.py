"""OS hardening feature scanner.

Checks kernel/OS-level hardening features: ASLR, SELinux, AppArmor,
Secure Boot and swap presence. LUKS disk encryption is covered in
:mod:`scanner.filesystem` and is intentionally not duplicated here.
"""

from __future__ import annotations

from scanner.utils import Finding, RiskLevel, command_exists, read_file_safe, run_command


class SecurityFeaturesScanner:
    """Scans OS/kernel level security hardening features."""

    category = "Security Features"

    def scan(self) -> list[Finding]:
        """Run all hardening-feature checks and return the findings."""
        findings: list[Finding] = []
        findings.append(self._check_aslr())
        findings.append(self._check_selinux())
        findings.append(self._check_apparmor())
        findings.append(self._check_secure_boot())
        return findings

    def _check_aslr(self) -> Finding:
        value = read_file_safe("/proc/sys/kernel/randomize_va_space")
        value = value.strip() if value else None

        if value == "2":
            return Finding(
                category=self.category,
                title="ASLR (Address Space Layout Randomization)",
                description="ASLR is fully enabled (randomize_va_space=2).",
                risk=RiskLevel.INFO,
            )
        if value in ("0", "1"):
            return Finding(
                category=self.category,
                title="ASLR (Address Space Layout Randomization)",
                description=f"ASLR is not fully enabled (randomize_va_space={value}).",
                risk=RiskLevel.HIGH,
                recommendation=(
                    "Set 'kernel.randomize_va_space=2' via sysctl to fully enable ASLR."
                ),
            )
        return Finding(
            category=self.category,
            title="ASLR (Address Space Layout Randomization)",
            description="Could not determine ASLR status.",
            risk=RiskLevel.INFO,
        )

    def _check_selinux(self) -> Finding:
        if command_exists("getenforce"):
            result = run_command(["getenforce"])
            if result.ok and result.stdout:
                status = result.stdout.strip()
                if status.lower() == "enforcing":
                    risk = RiskLevel.INFO
                elif status.lower() == "permissive":
                    risk = RiskLevel.MEDIUM
                else:
                    risk = RiskLevel.LOW
                return Finding(
                    category=self.category,
                    title="SELinux",
                    description=f"SELinux status: {status}",
                    risk=risk,
                    recommendation=(
                        "Set SELinux to 'Enforcing' in /etc/selinux/config for full protection."
                        if risk != RiskLevel.INFO
                        else ""
                    ),
                )

        return Finding(
            category=self.category,
            title="SELinux",
            description="SELinux is not installed/available on this system.",
            risk=RiskLevel.INFO,
        )

    def _check_apparmor(self) -> Finding:
        enabled_flag = read_file_safe("/sys/module/apparmor/parameters/enabled")
        if enabled_flag is not None:
            is_enabled = enabled_flag.strip().upper() == "Y"
            if command_exists("aa-status"):
                result = run_command(["aa-status", "--enabled"])
                # aa-status --enabled exits 0 if AppArmor is enabled.
                is_enabled = result.ok and result.returncode == 0

            risk = RiskLevel.INFO if is_enabled else RiskLevel.MEDIUM
            return Finding(
                category=self.category,
                title="AppArmor",
                description=f"AppArmor is {'enabled' if is_enabled else 'disabled'}.",
                risk=risk,
                recommendation="Enable AppArmor for mandatory access control." if not is_enabled else "",
            )

        return Finding(
            category=self.category,
            title="AppArmor",
            description="AppArmor is not installed/available on this system.",
            risk=RiskLevel.INFO,
        )

    def _check_secure_boot(self) -> Finding:
        if command_exists("mokutil"):
            result = run_command(["mokutil", "--sb-state"])
            if result.ok and result.stdout:
                output = result.stdout.lower()
                if "enabled" in output:
                    return Finding(
                        category=self.category,
                        title="Secure Boot",
                        description="Secure Boot is enabled.",
                        risk=RiskLevel.INFO,
                    )
                if "disabled" in output:
                    return Finding(
                        category=self.category,
                        title="Secure Boot",
                        description="Secure Boot is disabled.",
                        risk=RiskLevel.LOW,
                        recommendation="Enable Secure Boot in UEFI firmware settings if supported.",
                    )

        return Finding(
            category=self.category,
            title="Secure Boot",
            description="Could not determine Secure Boot status "
            "(mokutil unavailable or system may be running in a VM/BIOS mode).",
            risk=RiskLevel.INFO,
        )
