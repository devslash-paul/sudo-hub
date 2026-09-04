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
uv sync --frozen --extra dev
uv run --frozen pytest -q
```

For a local, non-root demo:

```console
.venv/bin/sudo-hub-server \
  --client-token development-token \
  --origin http://localhost:8787 \
  --rp-id localhost
```

Open `http://localhost:8787`, enroll a passkey using the one-time code printed by the server, then submit the built-in safe demo operation:

```console
.venv/bin/sudo-hub-request \
  --token development-token \
  demo.echo '{"message":"hello"}'
```

## Deployment

The repository includes repeatable installers for the trusted hub and for
request-only spoke systems. On the hub:

```console
cp deploy/hub.env.example deploy/hub.env
$EDITOR deploy/hub.env
sudo ./deploy/install-hub.sh
```

Open the HTTPS approval UI and enroll a passkey, then make the independent
root-owned credential copy and start the executor:

```console
sudo sudo-hub-install-credential
```

Transfer the generated scoped token to the spoke over a secure channel, then on
the spoke:

```console
cp deploy/spoke.env.example deploy/spoke.env
$EDITOR deploy/spoke.env
sudo ./deploy/install-spoke.sh deploy/spoke.env /secure/path/client-token-spoke
```

See [`deploy/README.md`](deploy/README.md) for the full sequence. The installers
use isolated virtual environments, install all Python dependencies, protect
configuration and bearer tokens, and can be rerun to upgrade a checkout.
Review the operation policy, reverse proxy, firewall, TLS origin, and systemd
sandboxing for the target environment before granting root access.

## Operations

The executor includes typed handlers for package refresh/upgrades, systemd service control, fstab mounts, Proxmox guest lifecycle/snapshots/backups, LXC bind mounts, and exact root command arrays. Policy validation happens before the command is constructed; requests never contain shell syntax.

## Repository hygiene

Runtime state is intentionally ignored. In particular, never commit bearer tokens, enrolled credentials, VAPID private keys, push subscription files, active leases, audit logs, or machine-specific deployment snapshots.

## License

Sudo Hub is licensed under the [MIT License](LICENSE).
