# Deployment

The hub runs the unprivileged web broker and root executor on the trusted
Proxmox host. A spoke only installs the request client and a scoped bearer
token; privileged container commands still execute through the hub's root
executor.

## Hub

1. Copy `hub.env.example` to the ignored `hub.env` and set the public origin,
   RP ID, spoke token mapping, and Proxmox VMID mapping.
2. Run `sudo ./deploy/install-hub.sh`. The installer creates the `sudo-hub`
   system user, installs the application and dependencies into
   `/opt/sudo-hub/.venv`, installs both systemd units, and starts the broker.
3. Open the approval UI and enroll the owner's passkey.
4. Run `sudo sudo-hub-install-credential`. This makes a root-owned copy of the
   enrolled credential and starts the executor.

The broker creates the scoped token at the path configured by
`SPOKE_TOKEN_SPEC`. Transfer that token to the spoke over a secure channel.

## Spoke

1. Copy `spoke.env.example` to the ignored `spoke.env`. Set the hub URL and the
   local user that will submit requests.
2. Place the transferred token at `deploy/client-token-spoke` or pass its path
   as the second installer argument.
3. Run `sudo ./deploy/install-spoke.sh [config-path] [token-path]`.
4. Start a new login session so the configured user receives its
   `sudo-hub-spoke` supplementary group, then use `sudo-hub-spoke-request`.

Both installers are idempotent and can be rerun to upgrade an existing source
checkout. Review the unit sandboxing and operation policy before production use.
