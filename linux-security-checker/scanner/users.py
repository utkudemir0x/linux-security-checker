
from __future__ import annotations

from scanner.utils import Finding, RiskLevel, is_root, read_file_safe, run_command


class UserSecurityScanner:
    """Scans local user accounts for common misconfigurations."""

    category = "Users"

    def scan(self) -> list[Finding]:
        """Run all user-related checks and return the findings."""
        findings: list[Finding] = []
        findings.extend(self._check_uid_zero())
        findings.extend(self._check_sudo_members())
        findings.extend(self._check_shadow_accounts())
        findings.extend(self._check_last_logins())
        return findings

    def _read_passwd_entries(self) -> list[list[str]]:
        content = read_file_safe("/etc/passwd")
        if not content:
            return []
        entries = []
        for line in content.splitlines():
            line = line.strip()
            if not line or line.startswith("#"):
                continue
            fields = line.split(":")
            if len(fields) >= 7:
                entries.append(fields)
        return entries

    def _check_uid_zero(self) -> list[Finding]:
        findings: list[Finding] = []
        entries = self._read_passwd_entries()
        uid_zero_users = [e[0] for e in entries if e[2] == "0" and e[0] != "root"]

        if uid_zero_users:
            findings.append(
                Finding(
                    category=self.category,
                    title="Additional UID 0 (root-equivalent) accounts found",
                    description=(
                        "The following non-'root' accounts have UID 0, granting them full "
                        f"root privileges: {', '.join(uid_zero_users)}"
                    ),
                    risk=RiskLevel.CRITICAL,
                    recommendation=(
                        "Remove or change the UID of these accounts; only 'root' should ever "
                        "have UID 0."
                    ),
                )
            )
        else:
            findings.append(
                Finding(
                    category=self.category,
                    title="UID 0 accounts",
                    description="Only 'root' has UID 0, as expected.",
                    risk=RiskLevel.INFO,
                )
            )
        return findings

    def _check_sudo_members(self) -> list[Finding]:
        findings: list[Finding] = []
        members: set[str] = set()

        for group_name in ("sudo", "wheel"):
            result = run_command(["getent", "group", group_name])
            if result.ok and result.returncode == 0 and result.stdout:
                # Format: group_name:x:gid:user1,user2,...
                parts = result.stdout.strip().split(":")
                if len(parts) >= 4 and parts[3]:
                    members.update(u for u in parts[3].split(",") if u)

        if members:
            risk = RiskLevel.HIGH if len(members) > 5 else RiskLevel.INFO
            findings.append(
                Finding(
                    category=self.category,
                    title="Users with sudo privileges",
                    description=f"{len(members)} account(s) can escalate to root via sudo: "
                    f"{', '.join(sorted(members))}",
                    risk=risk,
                    recommendation=(
                        "Review this list regularly and apply least-privilege; remove "
                        "unnecessary members."
                        if risk != RiskLevel.INFO
                        else ""
                    ),
                )
            )
        else:
            findings.append(
                Finding(
                    category=self.category,
                    title="Users with sudo privileges",
                    description="No members found in 'sudo' or 'wheel' groups "
                    "(or groups could not be queried).",
                    risk=RiskLevel.INFO,
                )
            )
        return findings

    def _check_shadow_accounts(self) -> list[Finding]:
        """Check /etc/shadow for locked accounts and empty passwords.

        Requires root privileges to read; degrades gracefully otherwise.
        """
        findings: list[Finding] = []
        content = read_file_safe("/etc/shadow")

        if content is None:
            findings.append(
                Finding(
                    category=self.category,
                    title="Shadow file analysis skipped",
                    description=(
                        "/etc/shadow could not be read (requires root). Empty-password and "
                        "lock-status checks were skipped."
                    ),
                    risk=RiskLevel.INFO,
                    recommendation="Re-run this tool with sudo/root for a complete audit.",
                )
            )
            return findings

        locked_accounts = []
        empty_password_accounts = []

        for line in content.splitlines():
            line = line.strip()
            if not line or line.startswith("#"):
                continue
            fields = line.split(":")
            if len(fields) < 2:
                continue
            username, password_hash = fields[0], fields[1]

            if password_hash.startswith("!") or password_hash.startswith("*"):
                locked_accounts.append(username)
            elif password_hash == "":
                empty_password_accounts.append(username)

        if empty_password_accounts:
            findings.append(
                Finding(
                    category=self.category,
                    title="Accounts with empty passwords",
                    description=(
                        "The following accounts have NO password set and can be logged into "
                        f"without authentication: {', '.join(empty_password_accounts)}"
                    ),
                    risk=RiskLevel.CRITICAL,
                    recommendation="Set a strong password or lock these accounts immediately "
                    "(`passwd -l <user>`).",
                )
            )

        findings.append(
            Finding(
                category=self.category,
                title="Locked accounts",
                description=f"{len(locked_accounts)} account(s) are locked/disabled.",
                risk=RiskLevel.INFO,
            )
        )

        if not is_root():
            findings.append(
                Finding(
                    category=self.category,
                    title="Running as non-root",
                    description="Some shadow-file checks may be incomplete without root.",
                    risk=RiskLevel.INFO,
                )
            )

        return findings

    def _check_last_logins(self) -> list[Finding]:
        findings: list[Finding] = []
        result = run_command(["last", "-n", "5"])
        if result.ok and result.stdout:
            lines = [ln for ln in result.stdout.splitlines() if ln.strip()][:5]
            description = "; ".join(lines) if lines else "No recent login records found."
            findings.append(
                Finding(
                    category=self.category,
                    title="Recent logins",
                    description=description,
                    risk=RiskLevel.INFO,
                )
            )
        else:
            findings.append(
                Finding(
                    category=self.category,
                    title="Recent logins",
                    description="Could not retrieve login history ('last' unavailable or empty).",
                    risk=RiskLevel.INFO,
                )
            )
        return findings
