#!/bin/sh
set -eu

if [ "$(id -u)" -ne 0 ]; then
    echo "install-spoke.sh must run as root" >&2
    exit 1
fi

project=$(CDPATH= cd -- "$(dirname -- "$0")/.." && pwd)
config=${1:-"$project/deploy/spoke.env"}
token=${2:-"$project/deploy/client-token-spoke"}

if [ ! -f "$config" ]; then
    echo "missing spoke config: copy deploy/spoke.env.example to deploy/spoke.env and edit it" >&2
    exit 1
fi
if [ ! -f "$token" ]; then
    echo "missing spoke token: securely copy the hub's scoped token to $token" >&2
    exit 1
fi

config_value() {
    sed -n "s/^$1=//p" "$config" | tail -n 1
}

client_user=$(config_value SUDO_HUB_CLIENT_USER)
token_file=$(config_value SUDO_HUB_TOKEN_FILE)
hub_url=$(config_value SUDO_HUB_URL)
if [ -z "$client_user" ] || [ -z "$token_file" ] || [ -z "$hub_url" ]; then
    echo "spoke config must define SUDO_HUB_CLIENT_USER, SUDO_HUB_TOKEN_FILE, and SUDO_HUB_URL" >&2
    exit 1
fi
case "$hub_url" in
    https://*) ;;
    *) echo "SUDO_HUB_URL must use HTTPS" >&2; exit 1 ;;
esac
if ! id "$client_user" >/dev/null 2>&1; then
    echo "spoke client user does not exist: $client_user" >&2
    exit 1
fi
case "$token_file" in
    */../*|*/..|*/./*) echo "SUDO_HUB_TOKEN_FILE must be normalized" >&2; exit 1 ;;
    /etc/sudo-hub/*) ;;
    *) echo "SUDO_HUB_TOKEN_FILE must be below /etc/sudo-hub" >&2; exit 1 ;;
esac

python3 -c 'import sys; raise SystemExit(sys.version_info < (3, 11))' || {
    echo "sudo-hub requires Python 3.11 or newer" >&2
    exit 1
}

if ! getent group sudo-hub-spoke >/dev/null 2>&1; then
    groupadd --system sudo-hub-spoke
fi
usermod -a -G sudo-hub-spoke "$client_user"

install -d -o root -g root -m 0755 /opt/sudo-hub-spoke /etc/sudo-hub
if [ ! -x /opt/sudo-hub-spoke/.venv/bin/python ]; then
    python3 -m venv /opt/sudo-hub-spoke/.venv
fi
/opt/sudo-hub-spoke/.venv/bin/python -m pip install --upgrade pip
/opt/sudo-hub-spoke/.venv/bin/python -m pip install --upgrade "$project"

install -o root -g sudo-hub-spoke -m 0640 "$config" /etc/sudo-hub/spoke.env
install -d -o root -g sudo-hub-spoke -m 0750 "$(dirname -- "$token_file")"
install -o root -g sudo-hub-spoke -m 0640 "$token" "$token_file"
install -o root -g root -m 0755 "$project/deploy/sudo-hub-spoke-request" /usr/local/bin/sudo-hub-spoke-request

echo "Spoke client installed. Start a new login session for group membership, then run:" >&2
echo "  sudo-hub-spoke-request OPERATION '{\"parameter\":\"value\"}'" >&2
