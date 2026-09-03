# Security policy

Please report suspected vulnerabilities privately through GitHub's security-advisory feature. Do not open a public issue containing exploit details, credentials, hostnames, or deployment data.

This software is pre-1.0 and currently has no supported release series. Before deployment, review the trust boundaries, operation policy, systemd sandboxing, Unix-socket ownership, reverse proxy, TLS origin, token storage, and audit retention for your environment.

If a credential or token may have been exposed, rotate it before reporting the issue. Removing a secret from the latest Git commit does not remove it from Git history.
