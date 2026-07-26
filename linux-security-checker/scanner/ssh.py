"""SSH daemon configuration security scanner.

Parses ``/etc/ssh/sshd_config`` (following simple ``Include``
directives is out of scope; the main file is normally sufficient for
an audit) and evaluates common hardening settings.
"""

from __future__ import annotations

from scanner.utils import Finding, RiskLevel, read_file_safe

DEFAULT_SSH_CONFIG_PATH = "/etc/ssh/sshd_config"


class SSHSecurityScanner:
    """Scans the OpenSSH server configuration for insecure settings."""

    category = "SSH"

    def __init__(self, config_path: str = DEFAULT_SSH_CONFIG_PATH) -> None:
        self.config_path = config_path

    def _parse_config(self) -> dict[str, str]:
        """Parse sshd_config into a lowercase-keyed dict of directives.

        sshd honors the FIRST occurrence of most directives, so later
        duplicate lines are ignored, matching sshd's own behavior.
        """
        content = read_file_safe(self.config_path)
        settings: dict[str, str] = {}
        if not content:
            return settings

        for raw_line in content.splitlines():
            line = raw_line.strip()
            if not line or line.startswith("#"):
                continue
            parts = line.split(None, 1)
            if len(parts) != 2:
                continue
            key, value = parts[0].lower(), parts[1].strip()
            if key not in settings:
                settings[key] = value
        return settings

    def scan(self) -> list[Finding]:
        """Run all SSH hardening checks and return the findings."""
        settings = self._parse_config()

        if not settings:
            return [
                Finding(
                    category=self.category,
                    title="sshd_config not found or unreadable",
                    description=(
                        f"Could not read {self.config_path}. Either OpenSSH server is not "
                        "installed, or this process lacks permission to read the file."
                    ),
                    risk=RiskLevel.INFO,
                )
            ]

        findings: list[Finding] = []
        findings.append(self._check_permit_root_login(settings))
        findings.append(self._check_password_auth(settings))
        findings.append(self._check_port(settings))
        findings.append(self._check_allow_users(settings))
        findings.append(self._check_pubkey_auth(settings))
        findings.append(self._check_max_auth_tries(settings))
        return findings

    def _check_permit_root_login(self, settings: dict[str, str]) -> Finding:
        value = settings.get("permitrootlogin", "prohibit-password (default)").lower()
        if value in ("yes",):
            risk = RiskLevel.HIGH
            desc = "PermitRootLogin is set to 'yes': root can log in directly over SSH."
            rec = "Set 'PermitRootLogin no' (or 'prohibit-password') in sshd_config."
        elif value in ("no",):
            risk = RiskLevel.INFO
            desc = "PermitRootLogin is 'no': direct root SSH login is disabled."
            rec = ""
        else:
            risk = RiskLevel.LOW
            desc = f"PermitRootLogin is '{value}': root login is restricted but still possible."
            rec = "Prefer 'PermitRootLogin no' unless direct root access is required."
        return Finding(self.category, "PermitRootLogin", desc, risk, rec)

    def _check_password_auth(self, settings: dict[str, str]) -> Finding:
        value = settings.get("passwordauthentication", "yes (default)").lower()
        if "yes" in value:
            risk = RiskLevel.MEDIUM
            desc = "PasswordAuthentication is enabled: password-based SSH login is allowed."
            rec = "Disable password auth ('PasswordAuthentication no') and use SSH keys only."
        else:
            risk = RiskLevel.INFO
            desc = "PasswordAuthentication is disabled: only key-based login is allowed."
            rec = ""
        return Finding(self.category, "PasswordAuthentication", desc, risk, rec)

    def _check_port(self, settings: dict[str, str]) -> Finding:
        value = settings.get("port", "22")
        if value.strip() == "22":
            risk = RiskLevel.LOW
            desc = "SSH is running on the default port 22."
            rec = "Consider using a non-standard port to reduce automated scan/brute-force noise."
        else:
            risk = RiskLevel.INFO
            desc = f"SSH is running on a non-default port ({value})."
            rec = ""
        return Finding(self.category, "SSH Port", desc, risk, rec)

    def _check_allow_users(self, settings: dict[str, str]) -> Finding:
        if "allowusers" in settings or "allowgroups" in settings:
            desc = "Login is restricted via AllowUsers/AllowGroups."
            risk = RiskLevel.INFO
            rec = ""
        else:
            desc = "No AllowUsers/AllowGroups restriction is configured; any valid account may attempt SSH login."
            risk = RiskLevel.LOW
            rec = "Restrict SSH access to specific users/groups with AllowUsers or AllowGroups."
        return Finding(self.category, "AllowUsers / AllowGroups", desc, risk, rec)

    def _check_pubkey_auth(self, settings: dict[str, str]) -> Finding:
        value = settings.get("pubkeyauthentication", "yes (default)").lower()
        if "no" in value:
            risk = RiskLevel.MEDIUM
            desc = "PubkeyAuthentication is disabled."
            rec = "Enable PubkeyAuthentication and prefer key-based authentication."
        else:
            risk = RiskLevel.INFO
            desc = "PubkeyAuthentication is enabled."
            rec = ""
        return Finding(self.category, "PubkeyAuthentication", desc, risk, rec)

    def _check_max_auth_tries(self, settings: dict[str, str]) -> Finding:
        raw_value = settings.get("maxauthtries", "6 (default)")
        try:
            numeric = int(raw_value.split()[0])
        except (ValueError, IndexError):
            numeric = 6

        if numeric > 6:
            risk = RiskLevel.LOW
            desc = f"MaxAuthTries is set high ({raw_value}), allowing more brute-force attempts per connection."
            rec = "Lower MaxAuthTries to 3-4 to slow down brute-force attempts."
        else:
            risk = RiskLevel.INFO
            desc = f"MaxAuthTries is {raw_value}."
            rec = ""
        return Finding(self.category, "MaxAuthTries", desc, risk, rec)
