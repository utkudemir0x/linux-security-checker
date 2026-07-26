"""Network exposure scanner.

Uses ``ss`` (falling back to ``netstat``) to enumerate listening
TCP/UDP ports and established connections, and flags well-known
high-risk services when found listening (e.g. Telnet, unauthenticated
services bound to all interfaces).
"""

from __future__ import annotations

from dataclasses import dataclass

from scanner.utils import Finding, RiskLevel, command_exists, run_command

# Ports considered inherently risky when exposed, mapped to a short reason.
RISKY_PORTS = {
    23: "Telnet transmits credentials in plaintext.",
    21: "FTP transmits credentials in plaintext (consider SFTP/FTPS).",
    512: "rexec is legacy/unencrypted.",
    513: "rlogin is legacy/unencrypted.",
    514: "rsh is legacy/unencrypted.",
    2049: "NFS exposed publicly can leak filesystem data.",
    3306: "MySQL exposed to all interfaces increases attack surface.",
    5432: "PostgreSQL exposed to all interfaces increases attack surface.",
    6379: "Redis has historically shipped with no authentication by default.",
    27017: "MongoDB exposed to all interfaces increases attack surface.",
}


@dataclass
class ListeningSocket:
    """A single listening TCP/UDP socket."""

    proto: str
    local_address: str
    port: int
    process: str


class NetworkScanner:
    """Analyzes listening ports and active network connections."""

    category = "Network"

    def scan(self) -> list[Finding]:
        """Run all network checks and return the findings."""
        findings: list[Finding] = []
        listening = self._get_listening_sockets()

        if listening is None:
            findings.append(
                Finding(
                    category=self.category,
                    title="Could not enumerate listening sockets",
                    description="Neither 'ss' nor 'netstat' were available or usable.",
                    risk=RiskLevel.INFO,
                )
            )
            return findings

        findings.append(
            Finding(
                category=self.category,
                title="Listening services",
                description=self._summarize_listening(listening),
                risk=RiskLevel.INFO,
            )
        )
        findings.extend(self._check_risky_ports(listening))
        findings.extend(self._check_connection_counts())
        return findings

    def _summarize_listening(self, sockets: list[ListeningSocket]) -> str:
        if not sockets:
            return "No listening TCP/UDP sockets found."
        entries = [f"{s.proto}/{s.port} ({s.process or 'unknown'})" for s in sockets]
        return f"{len(sockets)} listening socket(s): " + ", ".join(sorted(set(entries)))

    def _get_listening_sockets(self) -> list[ListeningSocket] | None:
        if command_exists("ss"):
            return self._parse_ss()
        if command_exists("netstat"):
            return self._parse_netstat()
        return None

    def _parse_ss(self) -> list[ListeningSocket] | None:
        result = run_command(["ss", "-tulnp"])
        if not result.ok:
            return None

        sockets: list[ListeningSocket] = []
        for line in result.stdout.splitlines()[1:]:  # skip header
            parts = line.split()
            if len(parts) < 5:
                continue
            proto = parts[0]
            local_address = parts[4]
            port = self._extract_port(local_address)
            process = ""
            if "users:" in line:
                process = line.split("users:", 1)[1].strip()
            if port is not None:
                sockets.append(ListeningSocket(proto, local_address, port, process))
        return sockets

    def _parse_netstat(self) -> list[ListeningSocket] | None:
        result = run_command(["netstat", "-tulnp"])
        if not result.ok:
            return None

        sockets: list[ListeningSocket] = []
        for line in result.stdout.splitlines():
            if not line.lower().startswith(("tcp", "udp")):
                continue
            parts = line.split()
            if len(parts) < 4:
                continue
            proto = parts[0]
            local_address = parts[3]
            port = self._extract_port(local_address)
            process = parts[-1] if len(parts) >= 7 else ""
            if port is not None:
                sockets.append(ListeningSocket(proto, local_address, port, process))
        return sockets

    @staticmethod
    def _extract_port(address: str) -> int | None:
        try:
            port_str = address.rsplit(":", 1)[-1]
            return int(port_str)
        except (ValueError, IndexError):
            return None

    def _check_risky_ports(self, sockets: list[ListeningSocket]) -> list[Finding]:
        findings: list[Finding] = []
        seen_ports: set[int] = set()
        for sock in sockets:
            if sock.port in RISKY_PORTS and sock.port not in seen_ports:
                seen_ports.add(sock.port)
                findings.append(
                    Finding(
                        category=self.category,
                        title=f"Potentially risky service on port {sock.port}",
                        description=RISKY_PORTS[sock.port] + f" (bound to {sock.local_address})",
                        risk=RiskLevel.HIGH if sock.port in (23, 21, 6379) else RiskLevel.MEDIUM,
                        recommendation="Restrict this service to localhost/VPN or disable it if unused.",
                    )
                )
        return findings

    def _check_connection_counts(self) -> list[Finding]:
        findings: list[Finding] = []
        if not command_exists("ss"):
            return findings

        tcp_result = run_command(["ss", "-tn", "state", "established"])
        if tcp_result.ok:
            count = max(len(tcp_result.stdout.splitlines()) - 1, 0)
            findings.append(
                Finding(
                    category=self.category,
                    title="Established TCP connections",
                    description=f"{count} established TCP connection(s) currently open.",
                    risk=RiskLevel.INFO,
                )
            )

        udp_result = run_command(["ss", "-un"])
        if udp_result.ok:
            count = max(len(udp_result.stdout.splitlines()) - 1, 0)
            findings.append(
                Finding(
                    category=self.category,
                    title="UDP sockets",
                    description=f"{count} UDP socket(s) currently open.",
                    risk=RiskLevel.INFO,
                )
            )
        return findings
