#!/bin/sh
set -eu

project=$(CDPATH= cd -- "$(dirname -- "$0")/.." && pwd)
credential=${1:-"$project/data/credential.json"}
config=${2:-"$project/deploy/sudo-hub.env"}
if [ ! -f "$config" ]; then
    echo "missing deployment config: copy deploy/sudo-hub.env.example to deploy/sudo-hub.env and edit it" >&2
    exit 1
fi
install -d -o root -g root -m 0755 /opt/sudo-hub /opt/sudo-hub/src /etc/codex-approval /etc/sudo-hub
cp -a "$project/src/codex_approval" /opt/sudo-hub/src/
chown -R root:root /opt/sudo-hub
find /opt/sudo-hub -type d -exec chmod 0755 {} \;
find /opt/sudo-hub -type f -exec chmod 0644 {} \;
install -o root -g root -m 0600 "$credential" /etc/codex-approval/credential.json
install -o root -g root -m 0600 "$config" /etc/sudo-hub/sudo-hub.env
install -o root -g root -m 0644 "$project/deploy/codex-approval-executor.service" /etc/systemd/system/codex-approval-executor.service
systemctl daemon-reload
systemctl enable --now codex-approval-executor.service
systemctl restart codex-approval-executor.service
