"""Service analysis scanner.

Checks the running/enabled status of common security-relevant services
(SSH, web servers, FTP, Samba, databases, Docker) via ``systemctl``,
and, when Docker is present, inspects running containers for
privileged mode.
"""

from __future__ import annotations

from scanner.utils import Finding, RiskLevel, command_exists, run_command

# Map a friendly service name to the possible systemd unit names it may
# be registered under across the supported distributions.
SERVICE_UNIT_CANDIDATES: dict[str, list[str]] = {
    "SSH": ["sshd", "ssh"],
    "Apache": ["apache2", "httpd"],
    "Nginx": ["nginx"],
    "FTP": ["vsftpd", "proftpd", "pure-ftpd"],
    "Samba": ["smbd", "samba"],
    "Docker": ["docker"],
    "MySQL": ["mysql", "mysqld", "mariadb"],
    "PostgreSQL": ["postgresql"],
}

# Services that are inherently higher risk simply by being exposed,
# regardless of configuration (e.g. plaintext protocols).
INHERENTLY_RISKY_SERVICES = {"FTP"}


class ServiceScanner:
    """Checks status of common services and Docker container hygiene."""

    category = "Services"

    def scan(self) -> list[Finding]:
        """Run all service checks and return the findings."""
        findings: list[Finding] = []
        findings.extend(self._check_services())
        findings.extend(self._check_docker())
        return findings

    def _check_services(self) -> list[Finding]:
        findings: list[Finding] = []
        if not command_exists("systemctl"):
            findings.append(
                Finding(
                    category=self.category,
                    title="Service status check skipped",
                    description="'systemctl' is not available on this system (non-systemd distro?).",
                    risk=RiskLevel.INFO,
                )
            )
            return findings

        for friendly_name, unit_candidates in SERVICE_UNIT_CANDIDATES.items():
            status = self._find_service_status(unit_candidates)
            if status is None:
                findings.append(
                    Finding(
                        category=self.category,
                        title=f"{friendly_name} service",
                        description=f"{friendly_name} does not appear to be installed.",
                        risk=RiskLevel.INFO,
                    )
                )
                continue

            unit_name, is_active, is_enabled = status
            if is_active and friendly_name in INHERENTLY_RISKY_SERVICES:
                risk = RiskLevel.MEDIUM
                recommendation = (
                    f"{friendly_name} transmits data/credentials in plaintext by default; "
                    "consider a secure alternative (e.g. SFTP) or restrict access."
                )
            else:
                risk = RiskLevel.INFO
                recommendation = ""

            findings.append(
                Finding(
                    category=self.category,
                    title=f"{friendly_name} service ({unit_name})",
                    description=(
                        f"active={'yes' if is_active else 'no'}, "
                        f"enabled_at_boot={'yes' if is_enabled else 'no'}"
                    ),
                    risk=risk,
                    recommendation=recommendation,
                )
            )
        return findings

    def _find_service_status(
        self, unit_candidates: list[str]
    ) -> tuple[str, bool, bool] | None:
        """Return (unit_name, is_active, is_enabled) for the first known unit, else None."""
        for unit in unit_candidates:
            exists_result = run_command(["systemctl", "list-unit-files", f"{unit}.service"])
            if not exists_result.ok or unit not in exists_result.stdout:
                continue

            active_result = run_command(["systemctl", "is-active", unit])
            enabled_result = run_command(["systemctl", "is-enabled", unit])
            is_active = active_result.ok and active_result.stdout.strip() == "active"
            is_enabled = enabled_result.ok and enabled_result.stdout.strip() == "enabled"
            return unit, is_active, is_enabled
        return None

    def _check_docker(self) -> list[Finding]:
        findings: list[Finding] = []
        if not command_exists("docker"):
            findings.append(
                Finding(
                    category=self.category,
                    title="Docker",
                    description="Docker is not installed.",
                    risk=RiskLevel.INFO,
                )
            )
            return findings

        ps_result = run_command(["docker", "ps", "--format", "{{.Names}}"])
        if not ps_result.ok:
            findings.append(
                Finding(
                    category=self.category,
                    title="Docker",
                    description="Docker is installed but could not be queried "
                    "(daemon may not be running, or permission denied).",
                    risk=RiskLevel.INFO,
                )
            )
            return findings

        container_names = [name for name in ps_result.stdout.splitlines() if name.strip()]
        findings.append(
            Finding(
                category=self.category,
                title="Docker containers running",
                description=f"{len(container_names)} container(s) currently running"
                + (f": {', '.join(container_names)}" if container_names else "."),
                risk=RiskLevel.INFO,
            )
        )

        privileged_containers = self._find_privileged_containers(container_names)
        if privileged_containers:
            findings.append(
                Finding(
                    category=self.category,
                    title="Privileged Docker containers detected",
                    description=(
                        "The following containers run with --privileged, giving them "
                        f"near-full host access: {', '.join(privileged_containers)}"
                    ),
                    risk=RiskLevel.CRITICAL,
                    recommendation=(
                        "Avoid --privileged; grant only the specific capabilities a container "
                        "needs via --cap-add."
                    ),
                )
            )
        return findings

    def _find_privileged_containers(self, container_names: list[str]) -> list[str]:
        privileged = []
        for name in container_names:
            inspect_result = run_command(
                ["docker", "inspect", "--format", "{{json .HostConfig.Privileged}}", name]
            )
            if inspect_result.ok and inspect_result.stdout.strip().lower() == "true":
                privileged.append(name)
        return privileged
