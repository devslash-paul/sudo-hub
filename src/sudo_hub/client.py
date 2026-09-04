from __future__ import annotations

import argparse
import json
import platform
import time
import urllib.request


def call(url, token, method="GET", value=None):
    data = json.dumps(value).encode() if value is not None else None
    request = urllib.request.Request(url, data=data, method=method, headers={
        "Authorization": f"Bearer {token}", "Content-Type": "application/json"
    })
    with urllib.request.urlopen(request, timeout=10) as response:
        return json.load(response)


def main():
    parser = argparse.ArgumentParser()
    parser.add_argument("--url", default="http://localhost:8787")
    token = parser.add_mutually_exclusive_group(required=True)
    token.add_argument("--token")
    token.add_argument("--token-file")
    parser.add_argument("--requester", default="sudo-hub-client")
    parser.add_argument("--task-id")
    parser.add_argument("--lease", action="store_true", help="request a short guest command lease")
    parser.add_argument("--duration", type=int, default=60)
    parser.add_argument("--max-commands", type=int, default=20)
    parser.add_argument("--group")
    parser.add_argument("--goal")
    parser.add_argument("--timeout", type=int, default=120)
    parser.add_argument("operation", nargs="?")
    parser.add_argument("parameters", nargs="?", type=json.loads)
    args = parser.parse_args()
    client_token = args.token or open(args.token_file).read().strip()
    if args.lease:
        if not args.task_id or not args.group or not args.goal:
            parser.error("--lease requires --task-id, --group, and --goal")
        operation = "guest.command.lease"
        parameters = {"duration":args.duration, "max_commands":args.max_commands, "group":args.group, "goal":args.goal}
    else:
        if args.operation is None or args.parameters is None:
            parser.error("operation and parameters are required unless --lease is used")
        operation, parameters = args.operation, args.parameters
    created = call(args.url + "/api/client/requests", client_token, "POST", {
        "operation": operation, "parameters": parameters,
        "requester": args.requester, "host": platform.node(), "taskId":args.task_id,
    })
    print(f"Waiting for approval: {created['id']}")
    deadline = time.time() + args.timeout
    while time.time() < deadline:
        current = call(args.url + "/api/request/" + created["id"], client_token)
        if current["state"] in {"completed", "denied"}:
            print(json.dumps(current, indent=2))
            raise SystemExit(0 if current["state"] == "completed" else 1)
        time.sleep(1)
    raise SystemExit("approval timed out")


if __name__ == "__main__":
    main()
