from __future__ import annotations

import argparse
import hashlib
import json
import os
import pwd
import re
import secrets
import socket
import struct
import subprocess
import time
from pathlib import Path

from .model import Request, canonical_json
from .operations import PolicyError, build_target_plan, lease_command_is_read_only
from .webauthn import Credential, b64d, verify_assertion


class LeaseInvalid(PolicyError):
    pass


class LeaseMismatch(PolicyError):
    pass


class Executor:
    def __init__(self, credential_file: Path, origin: str, rp_id: str, audit_file: Path, allowed_uid: int, container_targets: dict[str, str] | None = None, root_uid: int = 0, lease_file: Path | None = None):
        self.credential_file = credential_file
        self.origin = origin
        self.rp_id = rp_id
        self.audit_file = audit_file
        self.allowed_uid = allowed_uid
        self.container_targets = container_targets or {}
        self.root_uid = root_uid
        self.lease_file = lease_file
        self.used = set()
        self.leases: dict[str, dict] = {}
        if audit_file.exists():
            for line in audit_file.read_text(errors="replace").splitlines():
                try:
                    value = json.loads(line)
                    if value.get("challenge_hash"):
                        self.used.add(value["challenge_hash"])
                except ValueError:
                    pass
        self._load_leases()

    def _load_leases(self):
        if self.lease_file is None or not self.lease_file.exists():
            return
        try:
            value = json.loads(self.lease_file.read_text())
        except (OSError, ValueError):
            return
        now = int(time.time())
        if isinstance(value, dict):
            self.leases = {
                lease_id: lease for lease_id, lease in value.items()
                if isinstance(lease_id, str) and isinstance(lease, dict)
                and isinstance(lease.get("expires_at"), int) and lease["expires_at"] >= now
                and isinstance(lease.get("remaining"), int) and lease["remaining"] > 0
            }

    def _save_leases(self):
        if self.lease_file is None:
            return
        now = int(time.time())
        self.leases = {lease_id: lease for lease_id, lease in self.leases.items()
                       if lease.get("expires_at", 0) >= now and lease.get("remaining", 0) > 0}
        self.lease_file.parent.mkdir(mode=0o700, parents=True, exist_ok=True)
        tmp = self.lease_file.with_suffix(".tmp")
        tmp.write_text(json.dumps(self.leases, separators=(",", ":")) + "\n")
        tmp.chmod(0o600)
        tmp.replace(self.lease_file)

    def credential(self) -> Credential:
        return Credential(**json.loads(self.credential_file.read_text()))

    def audit(self, value):
        value = {"timestamp": int(time.time()), **value}
        with self.audit_file.open("a") as output:
            output.write(json.dumps(value, sort_keys=True, separators=(",", ":")) + "\n")
            output.flush()
            os.fsync(output.fileno())

    def authorize(self, bundle: dict):
        raw = bundle["request"]
        request = Request(
            raw["operation"], raw["parameters"], raw["requester"], raw["host"],
            target=raw.get("target", "host"), task_id=raw.get("task_id"),
            id=raw["id"], created_at=raw["created_at"],
        )
        challenge = b64d(bundle["challenge"])
        if len(challenge) != 64 or challenge[:32] != request.digest:
            raise PolicyError("approval is not bound to this request")
        approved_at = struct.unpack(">Q", challenge[32:40])[0]
        if abs(int(time.time()) - approved_at) > 90:
            raise PolicyError("approval has expired")
        challenge_hash = hashlib.sha256(challenge).hexdigest()
        if challenge_hash in self.used:
            raise PolicyError("approval has already been used")
        verify_assertion(bundle["assertion"], self.credential(), challenge, self.origin, self.rp_id)
        plan = None if request.operation in {"container.command.lease", "command.lease", "approval.batch"} else build_target_plan(request.operation, request.parameters, target=request.target, container_targets=self.container_targets, root_uid=self.root_uid)
        return request, challenge_hash, plan

    @staticmethod
    def batch_key(operation: str, parameters: dict, target: str) -> str:
        return hashlib.sha256(canonical_json({"operation":operation, "parameters":parameters, "target":target})).hexdigest()

    def grant_batch(self, request: Request):
        duration = request.parameters.get("duration", 60)
        commands = request.parameters.get("requests")
        if not request.task_id or not isinstance(duration, int) or not 10 <= duration <= 300:
            raise PolicyError("batch requires a task and a duration between 10 and 300 seconds")
        if not isinstance(commands, list) or not 1 <= len(commands) <= 25:
            raise PolicyError("batch requests must contain between 1 and 25 exact operations")
        allowed: dict[str, int] = {}
        summaries = []
        for item in commands:
            if not isinstance(item, dict) or set(item) != {"operation", "parameters"}:
                raise PolicyError("each batch item must contain only operation and parameters")
            operation, parameters = item["operation"], item["parameters"]
            if not isinstance(operation, str) or not isinstance(parameters, dict) or operation in {"approval.batch", "container.command.lease", "command.lease"}:
                raise PolicyError("batch contains an invalid or nested operation")
            plan = build_target_plan(operation, parameters, target=request.target, container_targets=self.container_targets, root_uid=self.root_uid)
            key = self.batch_key(operation, parameters, request.target)
            allowed[key] = allowed.get(key, 0) + 1
            summaries.append(plan.summary)
        lease_id = secrets.token_urlsafe(32)
        expires_at = int(time.time()) + duration
        self.leases[lease_id] = {"kind":"batch", "target":request.target, "task_id":request.task_id,
                                 "expires_at":expires_at, "remaining":len(commands), "allowed":allowed}
        self._save_leases()
        return {"ok":True, "lease_id":lease_id, "expires_at":expires_at, "max_commands":len(commands),
                "summary":f"Allow {len(commands)} exact operations on {request.target} for {duration} seconds",
                "operations":summaries}

    def grant_lease(self, request: Request):
        duration = request.parameters.get("duration", 60)
        max_commands = request.parameters.get("max_commands", 20)
        group = request.parameters.get("group")
        goal = request.parameters.get("goal")
        if not request.task_id:
            raise PolicyError("lease target or task is invalid")
        if request.operation == "container.command.lease":
            if request.target not in self.container_targets:
                raise PolicyError("lease target or task is invalid")
            allowed_operation = "container.admin.command"
        elif request.operation == "command.lease" and request.target == "host":
            allowed_operation = "admin.command"
        else:
            raise PolicyError("command lease is not valid for this target")
        if not isinstance(group, str) or not re.fullmatch(r"[A-Za-z0-9][A-Za-z0-9 ._-]{2,63}", group):
            raise PolicyError("lease group must be a named task group of 3-64 characters")
        if not isinstance(goal, str) or not re.fullmatch(r"[^\x00-\x1f\x7f]{12,240}", goal.strip()):
            raise PolicyError("lease goal must explain the bounded task in 12-240 readable characters")
        if not isinstance(duration, int) or not 10 <= duration <= 300:
            raise PolicyError("lease duration must be between 10 and 300 seconds")
        if not isinstance(max_commands, int) or not 1 <= max_commands <= 50:
            raise PolicyError("lease max_commands must be between 1 and 50")
        lease_id = secrets.token_urlsafe(32)
        expires_at = int(time.time()) + duration
        self.leases[lease_id] = {
            "kind":"command", "operation":allowed_operation, "group":group, "goal":goal.strip(), "target": request.target, "task_id": request.task_id,
            "expires_at": expires_at, "remaining": max_commands,
        }
        self._save_leases()
        return {"ok":True, "lease_id":lease_id, "expires_at":expires_at, "max_commands":max_commands,
                "group":group, "goal":goal.strip(), "summary":f"Allow up to {max_commands} unlisted read-only root commands for task group '{group}' on {request.target} for {duration} seconds"}

    def authorize_lease(self, bundle: dict):
        raw = bundle["request"]
        request = Request(
            raw["operation"], raw["parameters"], raw["requester"], raw["host"],
            target=raw.get("target", "host"), task_id=raw.get("task_id"),
            id=raw["id"], created_at=raw["created_at"],
        )
        lease = self.leases.get(bundle.get("lease_id", ""))
        if (lease is None or lease["expires_at"] < int(time.time()) or lease["remaining"] <= 0
                or request.target != lease["target"]
                or request.task_id != lease["task_id"] or abs(int(time.time()) - request.created_at) > 30):
            raise LeaseInvalid("lease is invalid, expired, exhausted, or outside its task scope")
        if lease["kind"] == "command":
            if request.operation != lease["operation"]:
                raise LeaseMismatch("operation is outside this timed-sudo lease")
            if not lease_command_is_read_only(request.parameters):
                raise LeaseMismatch("timed sudo allows only read-only diagnostic commands")
        elif lease["kind"] == "batch":
            key = self.batch_key(request.operation, request.parameters, request.target)
            if lease["allowed"].get(key, 0) <= 0:
                raise LeaseMismatch("operation is not an unused exact member of this batch")
            lease["allowed"][key] -= 1
        else:
            raise PolicyError("lease type is invalid")
        plan = build_target_plan(request.operation, request.parameters, target=request.target, container_targets=self.container_targets, root_uid=self.root_uid)
        lease["remaining"] -= 1
        self._save_leases()
        return request, plan, lease["remaining"], lease["expires_at"]

    def handle(self, bundle: dict):
        request = None
        challenge_hash = None
        try:
            if "lease_id" in bundle:
                try:
                    request, plan, remaining, expires_at = self.authorize_lease(bundle)
                except LeaseMismatch as exc:
                    return {"ok":False, "lease_miss":True, "error":str(exc)}
                except LeaseInvalid as exc:
                    return {"ok":False, "lease_invalid":True, "error":str(exc)}
                except Exception as exc:
                    return {"ok":False, "lease_invalid":True, "error":str(exc)}
                self.audit({"event":"lease_used", "request_id":request.id, "operation":request.operation,
                            "task_id":request.task_id, "remaining":remaining, "argv":plan.argv})
                completed = subprocess.run(
                    plan.argv, stdin=subprocess.DEVNULL, stdout=subprocess.PIPE,
                    stderr=subprocess.STDOUT, text=True, timeout=plan.timeout,
                    env={"PATH":"/usr/sbin:/usr/bin:/sbin:/bin", "LANG":"C.UTF-8"}, cwd="/", check=False,
                )
                return {"ok":completed.returncode == 0, "exit_code":completed.returncode,
                        "summary":plan.summary, "output":completed.stdout[-32_000:],
                        "lease":{"remaining":remaining, "expires_at":expires_at}}
            request, challenge_hash, plan = self.authorize(bundle)
            # Mark the challenge used before invoking the operation. A crash can deny
            # a retry, but can never execute the same approval twice.
            self.used.add(challenge_hash)
            if request.operation in {"container.command.lease", "command.lease", "approval.batch"}:
                result = self.grant_batch(request) if request.operation == "approval.batch" else self.grant_lease(request)
                self.audit({"event":"lease_granted", "request_id":request.id, "task_id":request.task_id,
                            "target":request.target, "expires_at":result["expires_at"], "max_commands":result["max_commands"]})
                return result
            self.audit({"event":"accepted", "request_id":request.id, "operation":request.operation, "challenge_hash":challenge_hash, "argv":plan.argv})
            completed = subprocess.run(
                plan.argv, stdin=subprocess.DEVNULL, stdout=subprocess.PIPE,
                stderr=subprocess.STDOUT, text=True, timeout=plan.timeout,
                env={"PATH":"/usr/sbin:/usr/bin:/sbin:/bin", "LANG":"C.UTF-8"},
                cwd="/", check=False,
            )
            output = completed.stdout[-32_000:]
            result = {"ok": completed.returncode == 0, "exit_code": completed.returncode, "summary": plan.summary, "output": output}
            self.audit({"event":"completed", "request_id":request.id, "operation":request.operation, "challenge_hash":challenge_hash, "exit_code":completed.returncode})
            return result
        except subprocess.TimeoutExpired:
            result = {"ok":False, "error":"operation timed out"}
        except Exception as exc:
            result = {"ok":False, "error":str(exc)}
        self.audit({"event":"rejected", "request_id":getattr(request, "id", None), "challenge_hash":challenge_hash, "error":result["error"]})
        return result


def main():
    parser = argparse.ArgumentParser()
    parser.add_argument("--socket", type=Path, default=Path("/run/sudo-hub/executor.sock"))
    parser.add_argument("--credential", type=Path, default=Path("/etc/sudo-hub/credential.json"))
    parser.add_argument("--audit", type=Path, default=Path("/var/log/sudo-hub/audit.jsonl"))
    # RuntimeDirectory is removed when this service restarts. Keep short-lived
    # lease state under /var/lib so an in-window lease survives that restart.
    parser.add_argument("--lease-file", type=Path, default=Path("/var/lib/sudo-hub-executor/active-leases.json"))
    parser.add_argument("--origin", default="http://localhost:8787")
    parser.add_argument("--rp-id", default="localhost")
    peer = parser.add_mutually_exclusive_group()
    peer.add_argument("--allowed-user", default="sudo-hub")
    peer.add_argument("--allowed-uid", type=int)
    parser.add_argument("--container-target", action="append", default=[], metavar="NAME=VMID")
    args = parser.parse_args()
    container_targets = {}
    for item in args.container_target:
        name, separator, vmid = item.partition("=")
        if not separator or not name or not vmid:
            raise SystemExit("--container-target must be NAME=VMID")
        container_targets[name] = vmid
    try:
        allowed_uid = args.allowed_uid if args.allowed_uid is not None else pwd.getpwnam(args.allowed_user).pw_uid
    except KeyError as exc:
        raise SystemExit(f"allowed user does not exist: {args.allowed_user}") from exc
    executor = Executor(args.credential, args.origin, args.rp_id, args.audit, allowed_uid, container_targets, lease_file=args.lease_file)
    args.socket.parent.mkdir(mode=0o755, parents=True, exist_ok=True)
    os.chmod(args.socket.parent, 0o755)
    args.socket.unlink(missing_ok=True)
    with socket.socket(socket.AF_UNIX, socket.SOCK_STREAM) as server:
        server.bind(str(args.socket))
        os.chown(args.socket, allowed_uid, -1)
        os.chmod(args.socket, 0o600)
        server.listen(16)
        while True:
            connection, _ = server.accept()
            with connection:
                _, uid, _ = struct.unpack("3i", connection.getsockopt(socket.SOL_SOCKET, socket.SO_PEERCRED, struct.calcsize("3i")))
                if uid != allowed_uid:
                    connection.sendall(b'{"ok":false,"error":"peer is not allowed"}\n')
                    continue
                data = b""
                while not data.endswith(b"\n") and len(data) <= 65_536:
                    chunk = connection.recv(8192)
                    if not chunk:
                        break
                    data += chunk
                if len(data) > 65_536:
                    result = {"ok":False, "error":"request is too large"}
                else:
                    try:
                        result = executor.handle(json.loads(data))
                    except Exception as exc:
                        result = {"ok":False, "error":str(exc)}
                connection.sendall(json.dumps(result, separators=(",", ":")).encode() + b"\n")


if __name__ == "__main__":
    main()
