"""Linux Security Checker - scanner package.

This package contains modular scanners that each analyze a specific
security domain of a Linux system (users, SSH, firewall, network,
filesystem, permissions, packages, services and hardening features)
and produce a list of :class:`scanner.utils.Finding` objects that are
aggregated into a final report by :mod:`scanner.report`.

The tool is intended for DEFENSIVE security auditing only: it reads
system configuration and state, it never modifies the system, exploits
anything, or performs any offensive action.
"""

__version__ = "1.0.0"
