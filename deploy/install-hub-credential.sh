#!/bin/sh
set -eu

if [ "$(id -u)" -ne 0 ]; then
    echo "sudo-hub-install-credential must run as root" >&2
    exit 1
fi

credential=${1:-/var/lib/sudo-hub/credential.json}
if [ ! -f "$credential" ]; then
    echo "credential not found: $credential" >&2
    exit 1
fi

install -d -o root -g root -m 0755 /etc/sudo-hub
install -o root -g root -m 0600 "$credential" /etc/sudo-hub/credential.json
systemctl enable --now sudo-hub-executor.service
systemctl restart sudo-hub-executor.service
