
from __future__ import annotations

from scanner.utils import Finding, RiskLevel, command_exists, run_command


class FirewallScanner:
    """Detects and evaluates the active firewall solution."""

    category = "Firewall"

    def scan(self) -> list[Finding]:
        """Run all firewall checks and return the findings."""
        findings: list[Finding] = []
        active_firewalls: list[str] = []

        ufw_finding, ufw_active = self._check_ufw()
        if ufw_finding:
            findings.append(ufw_finding)
        if ufw_active:
            active_firewalls.append("UFW")

        firewalld_finding, firewalld_active = self._check_firewalld()
        if firewalld_finding:
            findings.append(firewalld_finding)
        if firewalld_active:
            active_firewalls.append("firewalld")

        nft_finding, nft_active = self._check_nftables()
        if nft_finding:
            findings.append(nft_finding)
        if nft_active:
            active_firewalls.append("nftables")

        iptables_finding, iptables_active = self._check_iptables()
        if iptables_finding:
            findings.append(iptables_finding)
        if iptables_active:
            active_firewalls.append("iptables")

        if not active_firewalls:
            findings.append(
                Finding(
                    category=self.category,
                    title="No active firewall detected",
                    description=(
                        "None of UFW, firewalld, nftables, or iptables appear to have any "
                        "active rules blocking traffic."
                    ),
                    risk=RiskLevel.CRITICAL,
                    recommendation=(
                        "Enable and configure a firewall (e.g. 'ufw enable' or "
                        "'systemctl enable --now firewalld') with a default-deny inbound policy."
                    ),
                )
            )
        else:
            findings.append(
                Finding(
                    category=self.category,
                    title="Active firewall(s) detected",
                    description=f"Active firewall subsystem(s): {', '.join(active_firewalls)}",
                    risk=RiskLevel.INFO,
                )
            )

        return findings

    def _check_ufw(self) -> tuple[Finding | None, bool]:
        if not command_exists("ufw"):
            return None, False
        result = run_command(["ufw", "status"])
        if not result.ok:
            return None, False
        is_active = "status: active" in result.stdout.lower()
        risk = RiskLevel.INFO if is_active else RiskLevel.MEDIUM
        desc = result.stdout.splitlines()[0] if result.stdout else "UFW status unknown."
        return (
            Finding(
                category=self.category,
                title="UFW status",
                description=desc,
                risk=risk,
                recommendation="" if is_active else "Enable UFW with 'sudo ufw enable'.",
            ),
            is_active,
        )

    def _check_firewalld(self) -> tuple[Finding | None, bool]:
        if not command_exists("firewall-cmd"):
            return None, False
        result = run_command(["firewall-cmd", "--state"])
        if not result.ok:
            return None, False
        is_active = result.returncode == 0 and "running" in result.stdout.lower()
        risk = RiskLevel.INFO if is_active else RiskLevel.MEDIUM
        return (
            Finding(
                category=self.category,
                title="firewalld status",
                description=f"firewalld state: {result.stdout or 'not running'}",
                risk=risk,
                recommendation="" if is_active
                else "Start firewalld with 'systemctl enable --now firewalld'.",
            ),
            is_active,
        )

    def _check_nftables(self) -> tuple[Finding | None, bool]:
        if not command_exists("nft"):
            return None, False
        result = run_command(["nft", "list", "ruleset"])
        if not result.ok:
            return None, False
        has_rules = bool(result.stdout.strip())
        return (
            Finding(
                category=self.category,
                title="nftables ruleset",
                description=(
                    f"nftables has {'a non-empty' if has_rules else 'no'} active ruleset."
                ),
                risk=RiskLevel.INFO if has_rules else RiskLevel.INFO,
            ),
            has_rules,
        )

    def _check_iptables(self) -> tuple[Finding | None, bool]:
        if not command_exists("iptables"):
            return None, False
        result = run_command(["iptables", "-L", "-n"])
        if not result.ok:
            return None, False
        # Consider iptables "active" if any chain has rules beyond the
        # default ACCEPT policy headers.
        lines = [ln for ln in result.stdout.splitlines() if ln and not ln.startswith("Chain")
                 and not ln.startswith("target")]
        has_rules = len(lines) > 0
        return (
            Finding(
                category=self.category,
                title="iptables rules",
                description=f"iptables has {len(lines)} configured rule(s).",
                risk=RiskLevel.INFO,
            ),
            has_rules,
        )
