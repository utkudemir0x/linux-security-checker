"""Package manager scanner.

Detects the system's package manager (apt, dnf/yum, or pacman) and
reports how many packages have pending updates, distinguishing
security updates where the package manager makes that information
available.
"""

from __future__ import annotations

from scanner.utils import Finding, RiskLevel, command_exists, run_command


class PackageScanner:
    """Checks for pending package updates, highlighting security ones."""

    category = "Packages"

    def scan(self) -> list[Finding]:
        """Run the package update check appropriate for this distro."""
        if command_exists("apt"):
            return self._scan_apt()
        if command_exists("dnf"):
            return self._scan_dnf()
        if command_exists("yum"):
            return self._scan_yum()
        if command_exists("pacman"):
            return self._scan_pacman()

        return [
            Finding(
                category=self.category,
                title="No supported package manager found",
                description="Could not detect apt, dnf, yum, or pacman on this system.",
                risk=RiskLevel.INFO,
            )
        ]

    def _risk_for_count(self, count: int, security_count: int = 0) -> RiskLevel:
        if security_count > 0:
            return RiskLevel.HIGH if security_count > 5 else RiskLevel.MEDIUM
        if count > 50:
            return RiskLevel.MEDIUM
        if count > 0:
            return RiskLevel.LOW
        return RiskLevel.INFO

    def _scan_apt(self) -> list[Finding]:
        findings: list[Finding] = []
        # Refreshing the index (apt update) requires network + root and
        # has side effects, so we intentionally do NOT run it here; we
        # only inspect the currently cached index via --simulate.
        upgradable = run_command(["apt", "list", "--upgradable"])
        count = 0
        if upgradable.ok:
            lines = [ln for ln in upgradable.stdout.splitlines() if "/" in ln]
            count = len(lines)

        security_count = 0
        sim = run_command(["apt-get", "-s", "upgrade"])
        if sim.ok:
            security_count = sim.stdout.lower().count("-security")

        risk = self._risk_for_count(count, security_count)
        description = f"{count} package(s) have available updates"
        if security_count:
            description += f", including at least {security_count} from a -security source"
        description += "."

        findings.append(
            Finding(
                category=self.category,
                title="Pending package updates (apt)",
                description=description,
                risk=risk,
                recommendation=(
                    "Run 'sudo apt update && sudo apt upgrade' to apply pending updates."
                    if count
                    else ""
                ),
            )
        )
        return findings

    def _scan_dnf(self) -> list[Finding]:
        result = run_command(["dnf", "check-update"])
        # dnf check-update exits 100 when updates are available, 0 when
        # none are, and >0/!=100 on error.
        count = 0
        if result.ok and result.returncode in (0, 100):
            count = len(
                [
                    ln
                    for ln in result.stdout.splitlines()
                    if ln.strip() and not ln.startswith(("Last metadata", "Obsoleting"))
                ]
            )

        security_result = run_command(["dnf", "check-update", "--security"])
        security_count = 0
        if security_result.ok and security_result.returncode in (0, 100):
            security_count = len(
                [ln for ln in security_result.stdout.splitlines() if ln.strip()]
            )

        risk = self._risk_for_count(count, security_count)
        return [
            Finding(
                category=self.category,
                title="Pending package updates (dnf)",
                description=(
                    f"{count} package(s) have available updates "
                    f"({security_count} flagged as security updates)."
                ),
                risk=risk,
                recommendation="Run 'sudo dnf upgrade' to apply pending updates."
                if count
                else "",
            )
        ]

    def _scan_yum(self) -> list[Finding]:
        result = run_command(["yum", "check-update"])
        count = 0
        if result.ok and result.returncode in (0, 100):
            count = len([ln for ln in result.stdout.splitlines() if ln.strip()])

        risk = self._risk_for_count(count)
        return [
            Finding(
                category=self.category,
                title="Pending package updates (yum)",
                description=f"{count} package(s) have available updates.",
                risk=risk,
                recommendation="Run 'sudo yum update' to apply pending updates." if count else "",
            )
        ]

    def _scan_pacman(self) -> list[Finding]:
        findings: list[Finding] = []
        if command_exists("checkupdates"):
            result = run_command(["checkupdates"])
            count = len([ln for ln in result.stdout.splitlines() if ln.strip()]) if result.ok else 0
        else:
            # Fallback: -Qu requires a synced local sync db to be meaningful,
            # but works without network access if already synced.
            result = run_command(["pacman", "-Qu"])
            count = len([ln for ln in result.stdout.splitlines() if ln.strip()]) if result.ok else 0

        risk = self._risk_for_count(count)
        findings.append(
            Finding(
                category=self.category,
                title="Pending package updates (pacman)",
                description=f"{count} package(s) have available updates.",
                risk=risk,
                recommendation="Run 'sudo pacman -Syu' to apply pending updates." if count else "",
            )
        )
        return findings
