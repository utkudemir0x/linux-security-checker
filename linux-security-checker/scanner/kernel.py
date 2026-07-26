
from __future__ import annotations

import os
import platform
import shutil
import socket

from scanner.utils import (
    Finding,
    RiskLevel,
    bytes_to_human,
    get_distro_info,
    is_supported_distro,
    read_file_safe,
    seconds_to_uptime,
)


class SystemInfoScanner:
    """Gathers general system information used in the report header."""

    category = "System Info"

    def scan(self) -> list[Finding]:
        """Run all system information checks and return the findings."""
        findings: list[Finding] = []
        findings.append(self._kernel_finding())
        findings.append(self._distro_finding())
        findings.append(self._cpu_finding())
        findings.append(self._ram_finding())
        findings.extend(self._disk_findings())
        findings.append(self._uptime_finding())
        findings.append(self._hostname_finding())
        return findings

    def _kernel_finding(self) -> Finding:
        version = platform.release()
        return Finding(
            category=self.category,
            title="Kernel Version",
            description=f"Running kernel: {version}",
            risk=RiskLevel.INFO,
            recommendation="Keep the kernel updated to the latest LTS/stable release.",
        )

    def _distro_finding(self) -> Finding:
        distro = get_distro_info()
        supported = is_supported_distro(distro["id"])
        risk = RiskLevel.INFO if supported else RiskLevel.LOW
        note = "" if supported else " (distribution not officially supported by this tool)"
        return Finding(
            category=self.category,
            title="Linux Distribution",
            description=f"{distro['name']} (id={distro['id']}, version={distro['version']}){note}",
            risk=risk,
        )

    def _cpu_finding(self) -> Finding:
        model = "Unknown"
        cpuinfo = read_file_safe("/proc/cpuinfo")
        if cpuinfo:
            for line in cpuinfo.splitlines():
                if line.lower().startswith("model name"):
                    model = line.split(":", 1)[1].strip()
                    break
        cores = os.cpu_count() or 1
        return Finding(
            category=self.category,
            title="CPU",
            description=f"{model} ({cores} logical cores)",
            risk=RiskLevel.INFO,
        )

    def _ram_finding(self) -> Finding:
        meminfo = read_file_safe("/proc/meminfo")
        total_kb = 0
        available_kb = 0
        if meminfo:
            for line in meminfo.splitlines():
                if line.startswith("MemTotal:"):
                    total_kb = int(line.split()[1])
                elif line.startswith("MemAvailable:"):
                    available_kb = int(line.split()[1])
        total = bytes_to_human(total_kb * 1024)
        used_pct = 0.0
        if total_kb:
            used_pct = 100 * (1 - available_kb / total_kb)
        return Finding(
            category=self.category,
            title="RAM",
            description=f"Total: {total}, currently used: {used_pct:.1f}%",
            risk=RiskLevel.INFO,
        )

    def _disk_findings(self) -> list[Finding]:
        findings: list[Finding] = []
        try:
            usage = shutil.disk_usage("/")
        except OSError:
            return findings

        used_pct = 100 * usage.used / usage.total if usage.total else 0
        risk = RiskLevel.INFO
        recommendation = ""
        if used_pct >= 95:
            risk = RiskLevel.HIGH
            recommendation = "Free up disk space immediately; a full root filesystem can crash services."
        elif used_pct >= 85:
            risk = RiskLevel.MEDIUM
            recommendation = "Disk usage is high; plan cleanup or expansion soon."

        findings.append(
            Finding(
                category=self.category,
                title="Disk Usage (/)",
                description=(
                    f"Used: {bytes_to_human(usage.used)} / {bytes_to_human(usage.total)} "
                    f"({used_pct:.1f}%), Free: {bytes_to_human(usage.free)}"
                ),
                risk=risk,
                recommendation=recommendation,
            )
        )
        return findings

    def _uptime_finding(self) -> Finding:
        uptime_raw = read_file_safe("/proc/uptime")
        uptime_str = "Unknown"
        if uptime_raw:
            try:
                seconds = float(uptime_raw.split()[0])
                uptime_str = seconds_to_uptime(seconds)
            except (ValueError, IndexError):
                pass
        return Finding(
            category=self.category,
            title="Uptime",
            description=f"System has been running for {uptime_str}",
            risk=RiskLevel.INFO,
        )

    def _hostname_finding(self) -> Finding:
        return Finding(
            category=self.category,
            title="Hostname",
            description=socket.gethostname(),
            risk=RiskLevel.INFO,
        )
