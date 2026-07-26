# 🛡️ Linux Security Checker

A professional, open-source **command-line security auditing tool** for
Linux systems. It scans your system for common misconfigurations and
hardening gaps across users, SSH, firewall, network, filesystem,
permissions, packages, services, and OS-level protections, then
produces a clear, colorized report with an overall **Security Score**.

> ⚠️ **Defensive use only.** This tool is strictly READ-ONLY: it never
> modifies system configuration, exploits vulnerabilities, or performs
> any offensive action. It is designed for system administrators and
> security professionals to audit systems they own or are authorized
> to assess.

---

## ✨ Features

| Domain | What is checked |
|---|---|
| **System Info** | Kernel version, distribution, CPU, RAM, disk usage, uptime, hostname |
| **Users** | UID 0 accounts, sudo/wheel members, locked accounts, empty-password accounts, recent logins |
| **SSH** | `PermitRootLogin`, `PasswordAuthentication`, SSH port, `AllowUsers`/`AllowGroups`, `PubkeyAuthentication`, `MaxAuthTries` |
| **Firewall** | UFW, firewalld, nftables, iptables — detects if any firewall is actually active |
| **Network** | Listening TCP/UDP ports, established connections, known-risky exposed services |
| **Filesystem** | Mount hardening (`nosuid`/`nodev` on `/tmp`, `/dev/shm`), LUKS disk encryption, swap status |
| **Permissions** | SUID / SGID binaries, world-writable files, `777`-permission files, critical file modes (`/etc/shadow`, `/etc/passwd`) |
| **Packages** | Pending updates and security updates (apt / dnf / yum / pacman) |
| **Security Features** | ASLR, SELinux, AppArmor, Secure Boot |
| **Services** | SSH, Apache, Nginx, FTP, Samba, Docker, MySQL, PostgreSQL — active/enabled status; Docker privileged-container detection |

Every finding is classified into one of five risk levels:

| Level | Meaning |
|---|---|
| 🟢 `INFO` | Informational, no action needed |
| 🟡 `LOW` | Minor hardening opportunity |
| 🟠 `MEDIUM` | Should be addressed |
| 🔴 `HIGH` | Significant risk |
| ❌ `CRITICAL` | Immediate action required |

At the end of a scan, a **Security Score (0–100)** is calculated from
the weighted severity of all findings:


Security Score: 91/100  (Good)

❌ Critical : 0
🔴 High     : 1
🟠 Medium   : 3
🟡 Low      : 5
🟢 Info     : 9
```

---

## 🖥️ Supported Distributions

- Ubuntu
- Debian
- Kali Linux
- Arch Linux
- Fedora
- CentOS
- Rocky Linux

The tool degrades gracefully on other distributions and when a tool or
file it depends on is missing or unreadable (e.g. running without
root) — it simply reports what it could not check rather than
crashing.

---

## 📦 Installation

### Requirements

- Python 3.12+
- No third-party runtime dependencies (standard library only)

### Clone & run directly

```bash
git clone https://github.com/your-username/linux-security-checker.git
cd linux-security-checker
python3 main.py scan
```

### Install as a CLI command (editable install)

```bash
pip install -e .
linux-security-checker scan
```

### Development setup (for running the test suite)

```bash
pip install -r requirements.txt
python3 -m pytest tests/ -v
# or, with zero dependencies:
python3 -m unittest discover -s tests -v
```

---

## 🚀 Usage

Run a full scan with a colorized terminal report:

```bash
python3 main.py scan
```

Run with root privileges for a complete audit (required for
`/etc/shadow` analysis and some filesystem checks):

```bash
sudo python3 main.py scan
```

Output the report as JSON (for CI pipelines, dashboards, SIEM ingestion, etc.):

```bash
python3 main.py scan --json
```

Write the report to a file:

```bash
python3 main.py scan --json --output report.json
```

Only show findings at or above a given severity:

```bash
python3 main.py scan --min-severity HIGH
```

The tool exits with code `2` if any `CRITICAL` finding was detected,
`0` otherwise — handy for CI/CD gating.

---

## 📸 Example Output

> _Terminal screenshot placeholder — replace with an actual screenshot,
> e.g. `docs/screenshot.png`._

```text
================ Linux Security Checker - Scan Report ================
Generated at: 2026-07-26 20:06:44 UTC

## System Info
  🟢 [INFO    ] Kernel Version
           Running kernel: 6.8.0-generic
  ...

## Firewall
  ❌ [CRITICAL] No active firewall detected
           None of UFW, firewalld, nftables, or iptables appear to have
           any active rules blocking traffic.
           → Recommendation: Enable and configure a firewall...

------------------------------------------------------------------
Security Score: 65/100  (Needs Improvement)

  ❌ Critical : 1
  🔴 High     : 1
  🟠 Medium   : 0
  🟡 Low      : 0
  🟢 Info     : 33
------------------------------------------------------------------
```

---

## 🏗️ Project Structure

```text
linux-security-checker/
│
├── scanner/
│   ├── __init__.py
│   ├── utils.py          # Finding/RiskLevel model, shared helpers
│   ├── kernel.py          # System info (kernel, distro, CPU, RAM, disk...)
│   ├── users.py           # User account security
│   ├── ssh.py              # SSH daemon configuration
│   ├── firewall.py        # UFW / firewalld / nftables / iptables
│   ├── network.py         # Listening ports & connections
│   ├── filesystem.py      # Mount options, LUKS, swap
│   ├── permissions.py     # SUID / SGID / world-writable / 777
│   ├── packages.py        # Pending updates (apt/dnf/yum/pacman)
│   ├── security.py        # ASLR, SELinux, AppArmor, Secure Boot
│   ├── services.py        # systemd services + Docker
│   └── report.py          # Scoring, terminal & JSON rendering
│
├── tests/                  # unittest-based test suite (pytest compatible)
├── main.py                 # CLI entry point (argparse)
├── requirements.txt
├── pyproject.toml
└── README.md
```

### Design principles

- **Modular & OOP-based** — each domain is an independent scanner class
  exposing a single `scan() -> list[Finding]` method, making it trivial
  to add a new scanner: create a class, implement `scan()`, register it
  in `main.SCANNER_CLASSES`.
- **Fails soft, never crashes** — every external command and file read
  goes through defensive helpers (`run_command`, `read_file_safe`) that
  return empty/`None` on any error instead of raising, and `main.py`
  isolates any unexpected scanner exception so one failing check never
  aborts the whole scan.
- **Read-only** — no scanner ever writes to the filesystem, changes
  configuration, or executes anything beyond standard read-only system
  inspection commands (`ss`, `lsblk`, `systemctl status`, etc.).
- **Type-hinted & PEP 8 compliant** throughout.

---

## 🧪 Testing

```bash
python3 -m unittest discover -s tests -v
```

The suite covers the core data model (`Finding`, `RiskLevel`), the
scoring algorithm, JSON serialization, and the SSH configuration parser
with both hardened and insecure sample configs.

---

## 🤝 Contributing

Contributions are welcome! To add a new check or scanner:

1. Fork the repository and create a feature branch.
2. Add your scanner class under `scanner/` (or extend an existing one),
   following the `scan() -> list[Finding]` pattern.
3. Register new scanner classes in `SCANNER_CLASSES` in `main.py`.
4. Add unit tests under `tests/`.
5. Run `python3 -m unittest discover -s tests` and ensure everything
   passes.
6. Open a pull request describing the check and its rationale.

Please keep contributions focused on **defensive** security auditing.
Pull requests that add offensive/exploitation capabilities will not be
accepted.

---

## 📄 License

This project is licensed under the **MIT License** — see below.

```text
MIT License

Copyright (c) 2026 Linux Security Checker Contributors

Permission is hereby granted, free of charge, to any person obtaining a copy
of this software and associated documentation files (the "Software"), to deal
in the Software without restriction, including without limitation the rights
to use, copy, modify, merge, publish, distribute, sublicense, and/or sell
copies of the Software, and to permit persons to whom the Software is
furnished to do so, subject to the following conditions:

The above copyright notice and this permission notice shall be included in all
copies or substantial portions of the Software.

THE SOFTWARE IS PROVIDED "AS IS", WITHOUT WARRANTY OF ANY KIND, EXPRESS OR
IMPLIED, INCLUDING BUT NOT LIMITED TO THE WARRANTIES OF MERCHANTABILITY,
FITNESS FOR A PARTICULAR PURPOSE AND NONINFRINGEMENT. IN NO EVENT SHALL THE
AUTHORS OR COPYRIGHT HOLDERS BE LIABLE FOR ANY CLAIM, DAMAGES OR OTHER
LIABILITY, WHETHER IN AN ACTION OF CONTRACT, TORT OR OTHERWISE, ARISING FROM,
OUT OF OR IN CONNECTION WITH THE SOFTWARE OR THE USE OR OTHER DEALINGS IN THE
SOFTWARE.
```
