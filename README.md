# Sudo Hub

Sudo Hub is a small, phone-first approval broker for privileged Linux operations. A client submits a typed request to an unprivileged hub, the owner approves it with a WebAuthn passkey, and a separate root executor independently verifies the signed approval before running a policy-built command.

It supports a hub-and-spoke topology: a host token can request host operations, while independently scoped spoke tokens can request commands only inside configured Proxmox LXC guests.

> [!WARNING]
> This project is security-sensitive and pre-1.0. Read the code and adapt the policy to your environment before granting it root access. Do not expose the Python HTTP server directly to the public internet; put it behind authenticated TLS networking or a carefully configured reverse proxy.

## Security model

- The web broker runs unprivileged and cannot execute root commands itself.
- The root executor listens on a local Unix socket and accepts only one configured UID.
- The executor re-verifies WebAuthn assertions and binds them to a canonical request digest.
- Exact approvals are single-use and expire quickly.
- Declared batches bind every operation and argument in advance.
- Timed leases are task-, target-, time-, and count-bound, and accept only an allowlist of read-only commands.
- Shells, interpreters, relative executables, and writable/non-root-owned host executables are rejected.
- Scoped spoke tokens cannot authorize host operations.
- Accepted, completed, rejected, and leased operations are written to an append-only JSON-lines audit file (subject to host filesystem protections).

The broker and executor run on the trusted host. A spoke submits requests over HTTPS using its own bearer token; the host executor uses `pct exec` for an explicitly configured LXC ID.

## Development

Requires Python 3.11 or newer.

```console
python3 -m venv .venv
.venv/bin/pip install -e '.[dev]'
.venv/bin/pytest -q
```

For a local, non-root demo:

```console
.venv/bin/codex-approval-server \
  --client-token development-token \
  --origin http://localhost:8787 \
  --rp-id localhost
```

Open `http://localhost:8787`, enroll a passkey using the one-time code printed by the server, then submit the built-in safe demo operation:

```console
.venv/bin/codex-approval-request \
  --token development-token \
  demo.echo '{"message":"hello"}'
```

## Production outline

1. Create a locked-down `sudo-hub` system user, install the package into `/opt/sudo-hub/.venv`, and keep broker state in `/var/lib/sudo-hub` with mode `0700`.
2. Serve the broker through HTTPS. WebAuthn requires the configured `--origin` and `--rp-id` to exactly match the browser-visible relying party.
3. Create separate random bearer-token files for the host and every spoke. Never put tokens on command lines, in Git, or in unit files.
4. Copy the enrolled `credential.json` to `/etc/codex-approval/credential.json` with owner `root:root` and mode `0600` so the executor can verify approvals independently.
5. Configure the root executor with the `sudo-hub` user's Unix UID and explicit `NAME=VMID` spoke mappings. The broker and allowed socket peer must be the same UID.
6. Review and adapt `src/codex_approval/operations.py`; its Proxmox and filesystem policies are examples, not a universal safe policy.
7. Install and customize the example systemd units in `deploy/`.

Copy the tracked example to the ignored local deployment file and edit it:

```console
cp deploy/sudo-hub.env.example deploy/sudo-hub.env
$EDITOR deploy/sudo-hub.env
```

Both systemd units read the installed copy at `/etc/sudo-hub/sudo-hub.env`. Install it without making it world-readable:

```console
sudo install -o root -g root -m 0600 deploy/sudo-hub.env /etc/sudo-hub/sudo-hub.env
```

The file holds the browser origin/RP ID, Web Push contact, allowed requester UID, spoke name, spoke token-file mapping, and Proxmox VMID mapping. It must not contain bearer-token values; those stay in separate mode-`0600` runtime files.

The supplied units are templates. Their network dependencies, paths, user model, reverse proxy, firewall rules, and Proxmox mappings must be reviewed for the deployment host.

## Operations

The executor includes typed handlers for package refresh/upgrades, systemd service control, fstab mounts, Proxmox guest lifecycle/snapshots/backups, LXC bind mounts, and exact root command arrays. Policy validation happens before the command is constructed; requests never contain shell syntax.

## Repository hygiene

Runtime state is intentionally ignored. In particular, never commit bearer tokens, enrolled credentials, VAPID private keys, push subscription files, active leases, audit logs, or machine-specific deployment snapshots.

## License

No license has been granted yet. All rights are reserved unless the repository owner adds a license.
