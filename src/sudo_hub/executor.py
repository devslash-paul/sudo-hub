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
from .operations import (
    GUEST_LEASE_OPERATIONS,
    PolicyError,
    build_target_plan,
    lease_command_is_read_only,
    parse_guest_targets,
)
from .webauthn import Credential, b64d, verify_assertion


class LeaseInvalid(PolicyError):
    pass


class LeaseMismatch(PolicyError):
    pass


LEASE_OPERATIONS = GUEST_LEASE_OPERATIONS | {"command.lease", "approval.batch"}


class Executor:
    def __init__(self, credential_file: Path, origin: str, rp_id: str, audit_file: Path, allowed_uid: int, container_targets: dict[str, str] | None = None, root_uid: int = 0, lease_file: Path | None = None, *, guest_targets: dict[str, str] | None = None):
        self.credential_file = credential_file
        self.origin = origin
        self.rp_id = rp_id
        self.audit_file = audit_file
        self.allowed_uid = allowed_uid
        if guest_targets is not None and container_targets is not None:
            raise ValueError("use guest_targets or container_targets, not both")
        configured_targets = guest_targets if guest_targets is not None else (container_targets or {})
        self.guest_targets = parse_guest_targets([
            f"{name}={value}" for name, value in configured_targets.items()
        ])
        self.container_targets = self.guest_targets  # compatibility for pre-VM callers
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
            target_spec=raw.get("target_spec"),
            id=raw["id"], created_at=raw["created_at"],
        )
        self.validate_target_binding(request)
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
        plan = None if request.operation in LEASE_OPERATIONS else build_target_plan(request.operation, request.parameters, target=request.target, guest_targets=self.guest_targets, root_uid=self.root_uid)
        return request, challenge_hash, plan

    def validate_target_binding(self, request: Request):
        if request.target == "host":
            if request.target_spec is not None:
                raise PolicyError("host request must not include a guest target binding")
            return
        configured = self.guest_targets.get(request.target)
        if configured is None or request.target_spec != configured:
            raise PolicyError("request is not bound to the configured guest target")

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
            if not isinstance(operation, str) or not isinstance(parameters, dict) or operation in LEASE_OPERATIONS:
                raise PolicyError("batch contains an invalid or nested operation")
            plan = build_target_plan(operation, parameters, target=request.target, guest_targets=self.guest_targets, root_uid=self.root_uid)
            key = self.batch_key(operation, parameters, request.target)
            allowed[key] = allowed.get(key, 0) + 1
            summaries.append(plan.summary)
        lease_id = secrets.token_urlsafe(32)
        expires_at = int(time.time()) + duration
        self.leases[lease_id] = {"kind":"batch", "target":request.target, "target_spec":request.target_spec, "task_id":request.task_id,
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
        if request.operation in GUEST_LEASE_OPERATIONS:
            if request.target not in self.guest_targets:
                raise PolicyError("lease target or task is invalid")
            allowed_operation = (
                "container.admin.command"
                if request.operation == "container.command.lease"
                else "guest.admin.command"
            )
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
            "kind":"command", "operation":allowed_operation, "group":group, "goal":goal.strip(), "target": request.target, "target_spec":request.target_spec, "task_id": request.task_id,
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
            target_spec=raw.get("target_spec"),
            id=raw["id"], created_at=raw["created_at"],
        )
        self.validate_target_binding(request)
        lease = self.leases.get(bundle.get("lease_id", ""))
        if (lease is None or lease["expires_at"] < int(time.time()) or lease["remaining"] <= 0
                or request.target != lease["target"]
                or request.target_spec != lease.get("target_spec")
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
        plan = build_target_plan(request.operation, request.parameters, target=request.target, guest_targets=self.guest_targets, root_uid=self.root_uid)
        lease["remaining"] -= 1
        self._save_leases()
        return request, plan, lease["remaining"], lease["expires_at"]

    @staticmethod
    def execute_plan(plan):
        environment = {"PATH":"/usr/sbin:/usr/bin:/sbin:/bin", "LANG":"C.UTF-8"}
        if plan.result_format != "qemu-guest-agent":
            completed = subprocess.run(
                plan.argv, stdin=subprocess.DEVNULL, stdout=subprocess.PIPE,
                stderr=subprocess.STDOUT, text=True, timeout=plan.timeout,
                env=environment, cwd="/", check=False,
            )
            return {
                "ok": completed.returncode == 0,
                "exit_code": completed.returncode,
                "summary": plan.summary,
                "output": completed.stdout[-32_000:],
            }

        completed = subprocess.run(
            plan.argv, stdin=subprocess.DEVNULL, stdout=subprocess.PIPE,
            stderr=subprocess.PIPE, text=True, timeout=plan.timeout + 3,
            env=environment, cwd="/", check=False,
        )
        transport_output = (completed.stdout + completed.stderr)[-32_000:]
        if completed.returncode != 0:
            return {
                "ok": False,
                "exit_code": completed.returncode,
                "summary": plan.summary,
                "output": transport_output,
                "error": "QEMU Guest Agent command failed",
            }
        try:
            guest_result = json.loads(completed.stdout)
        except (TypeError, ValueError):
            return {
                "ok": False,
                "exit_code": 1,
                "summary": plan.summary,
                "output": transport_output,
                "error": "QEMU Guest Agent returned an invalid result",
            }
        if not isinstance(guest_result, dict) or not guest_result.get("exited"):
            return {
                "ok": False,
                "exit_code": 1,
                "summary": plan.summary,
                "output": transport_output,
                "error": "QEMU guest command did not finish before the timeout",
            }
        signal = guest_result.get("signal")
        exit_code = guest_result.get("exitcode")
        if not isinstance(exit_code, int):
            exit_code = 128 + signal if isinstance(signal, int) and 0 < signal < 128 else 1
        output = "".join(
            value for value in (guest_result.get("out-data"), guest_result.get("err-data"))
            if isinstance(value, str)
        )[-32_000:]
        return {
            "ok": exit_code == 0 and signal is None,
            "exit_code": exit_code,
            "summary": plan.summary,
            "output": output,
        }

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
                result = self.execute_plan(plan)
                result["lease"] = {"remaining":remaining, "expires_at":expires_at}
                return result
            request, challenge_hash, plan = self.authorize(bundle)
            # Mark the challenge used before invoking the operation. A crash can deny
            # a retry, but can never execute the same approval twice.
            self.used.add(challenge_hash)
            if request.operation in LEASE_OPERATIONS:
                result = self.grant_batch(request) if request.operation == "approval.batch" else self.grant_lease(request)
                self.audit({"event":"lease_granted", "request_id":request.id, "task_id":request.task_id,
                            "target":request.target, "expires_at":result["expires_at"], "max_commands":result["max_commands"]})
                return result
            self.audit({"event":"accepted", "request_id":request.id, "operation":request.operation, "challenge_hash":challenge_hash, "argv":plan.argv})
            result = self.execute_plan(plan)
            self.audit({"event":"completed", "request_id":request.id, "operation":request.operation, "challenge_hash":challenge_hash, "exit_code":result["exit_code"]})
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
    parser.add_argument("--guest-target", action="append", default=[], metavar="NAME=TYPE:VMID")
    parser.add_argument("--container-target", action="append", default=[], metavar="NAME=VMID", help=argparse.SUPPRESS)
    args = parser.parse_args()
    try:
        guest_targets = parse_guest_targets(args.guest_target, args.container_target)
    except PolicyError as exc:
        raise SystemExit(str(exc)) from exc
    try:
        allowed_uid = args.allowed_uid if args.allowed_uid is not None else pwd.getpwnam(args.allowed_user).pw_uid
    except KeyError as exc:
        raise SystemExit(f"allowed user does not exist: {args.allowed_user}") from exc
    executor = Executor(
        args.credential, args.origin, args.rp_id, args.audit, allowed_uid,
        lease_file=args.lease_file, guest_targets=guest_targets,
    )
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
