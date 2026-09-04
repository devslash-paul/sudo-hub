#!/bin/sh
set -eu

if [ "$(id -u)" -ne 0 ]; then
    echo "install-hub.sh must run as root" >&2
    exit 1
fi

project=$(CDPATH= cd -- "$(dirname -- "$0")/.." && pwd)
config=${1:-"$project/deploy/hub.env"}
credential=${2:-"/var/lib/sudo-hub/credential.json"}

if [ ! -f "$config" ]; then
    echo "missing hub config: copy deploy/hub.env.example to deploy/hub.env and edit it" >&2
    exit 1
fi
for key in APPROVAL_ORIGIN APPROVAL_RP_ID VAPID_SUBJECT SPOKE_TOKEN_SPEC SPOKE_TARGET_SPEC; do
    if ! grep -q "^${key}=." "$config"; then
        echo "hub config is missing $key" >&2
        exit 1
    fi
done
if grep -q 'example\.com' "$config"; then
    echo "hub config still contains example.com placeholders" >&2
    exit 1
fi
origin=$(sed -n 's/^APPROVAL_ORIGIN=//p' "$config" | tail -n 1)
case "$origin" in
    https://*) ;;
    *) echo "APPROVAL_ORIGIN must use HTTPS" >&2; exit 1 ;;
esac

python3 -c 'import sys; raise SystemExit(sys.version_info < (3, 11))' || {
    echo "sudo-hub requires Python 3.11 or newer" >&2
    exit 1
}

if ! id sudo-hub >/dev/null 2>&1; then
    useradd --system --home-dir /var/lib/sudo-hub --shell /usr/sbin/nologin sudo-hub
fi

install -d -o root -g root -m 0755 /opt/sudo-hub /etc/sudo-hub
if [ ! -x /opt/sudo-hub/.venv/bin/python ]; then
    python3 -m venv /opt/sudo-hub/.venv
fi
/opt/sudo-hub/.venv/bin/python -m pip install --upgrade pip
/opt/sudo-hub/.venv/bin/python -m pip install --upgrade "$project"

install -o root -g root -m 0600 "$config" /etc/sudo-hub/hub.env
install -o root -g root -m 0644 "$project/deploy/sudo-hub.service" /etc/systemd/system/sudo-hub.service
install -o root -g root -m 0644 "$project/deploy/sudo-hub-executor.service" /etc/systemd/system/sudo-hub-executor.service
install -o root -g root -m 0755 "$project/deploy/install-hub-credential.sh" /usr/local/sbin/sudo-hub-install-credential

systemctl daemon-reload
systemctl enable sudo-hub.service
systemctl restart sudo-hub.service
systemctl enable sudo-hub-executor.service

if [ -f "$credential" ]; then
    /usr/local/sbin/sudo-hub-install-credential "$credential"
else
    echo "Hub installed and broker started. Enroll a passkey, then run:" >&2
    echo "  sudo sudo-hub-install-credential /var/lib/sudo-hub/credential.json" >&2
fi
