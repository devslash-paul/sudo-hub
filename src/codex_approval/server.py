from __future__ import annotations

import argparse
import hmac
import json
import re
import secrets
import socket
import struct
import threading
import time
from dataclasses import asdict, dataclass
from http import HTTPStatus
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer
from pathlib import Path
from urllib.parse import urlparse

from .model import Request
from .webauthn import Credential, b64e, credential_from_registration, verify_assertion
from cryptography.hazmat.primitives import serialization
from cryptography.hazmat.primitives.asymmetric import ec


@dataclass(frozen=True)
class ClientScope:
    target: str
    operations: frozenset[str] | None = None

    def allows(self, operation: str) -> bool:
        return self.operations is None or operation in self.operations


TARGET_NAME = re.compile(r"^[a-z0-9][a-z0-9.-]{0,62}$")
TASK_ID = re.compile(r"^[A-Za-z0-9_-]{8,128}$")


class Broker:
    def __init__(self, data_dir: Path, origin: str, rp_id: str, client_token: str, enrollment_token: str, scoped_client_tokens: dict[str, ClientScope] | None = None, vapid_subject: str = "mailto:admin@example.com"):
        self.data_dir = data_dir
        self.origin = origin.rstrip("/")
        self.rp_id = rp_id
        self.client_tokens = {client_token: ClientScope("host")}
        self.client_tokens.update(scoped_client_tokens or {})
        self.enrollment_token = enrollment_token
        self.vapid_subject = vapid_subject
        self.requests: dict[str, Request] = {}
        self.leases: dict[tuple[str, str], str] = {}
        self.lease_expiries: dict[tuple[str, str], int] = {}
        self.challenges: dict[str, tuple[str, bytes, float, str | None]] = {}
        self.lock = threading.RLock()
        data_dir.mkdir(parents=True, exist_ok=True)
        self.credential_file = data_dir / "credential.json"
        self.push_file = data_dir / "push-subscriptions.json"
        self.vapid_file = data_dir / "vapid-private.pem"
        self.lease_file = data_dir / "active-leases.json"
        self._load_leases()
        self.credential = self._load_credential()
        self.push_subscriptions = self._load_push_subscriptions()
        self._ensure_vapid_key()

    def _load_leases(self):
        if not self.lease_file.exists():
            return
        try:
            entries = json.loads(self.lease_file.read_text())
        except (OSError, ValueError):
            return
        now = int(time.time())
        for entry in entries if isinstance(entries, list) else []:
            if (isinstance(entry, dict) and isinstance(entry.get("target"), str)
                    and isinstance(entry.get("task_id"), str)
                    and isinstance(entry.get("lease_id"), str)
                    and isinstance(entry.get("expires_at"), int)
                    and entry["expires_at"] >= now):
                key = (entry["target"], entry["task_id"])
                self.leases[key] = entry["lease_id"]
                self.lease_expiries[key] = entry["expires_at"]

    def _save_leases(self):
        now = int(time.time())
        entries = []
        for key, lease_id in list(self.leases.items()):
            expires_at = self.lease_expiries.get(key, 0)
            if expires_at < now:
                self.leases.pop(key, None)
                self.lease_expiries.pop(key, None)
                continue
            entries.append({"target":key[0], "task_id":key[1], "lease_id":lease_id,
                            "expires_at":expires_at})
        tmp = self.lease_file.with_suffix(".tmp")
        tmp.write_text(json.dumps(entries, separators=(",", ":")) + "\n")
        tmp.chmod(0o600)
        tmp.replace(self.lease_file)

    def client_scope(self, supplied: str) -> ClientScope | None:
        matched = None
        for token, scope in self.client_tokens.items():
            if supplied and hmac.compare_digest(supplied, token):
                matched = scope
        return matched

    def _load_credential(self) -> Credential | None:
        if not self.credential_file.exists():
            return None
        return Credential(**json.loads(self.credential_file.read_text()))

    def save_credential(self, credential: Credential):
        tmp = self.credential_file.with_suffix(".tmp")
        tmp.write_text(json.dumps(asdict(credential), indent=2) + "\n")
        tmp.chmod(0o600)
        tmp.replace(self.credential_file)
        self.credential = credential

    def _load_push_subscriptions(self):
        if not self.push_file.exists():
            return []
        try:
            value = json.loads(self.push_file.read_text())
            return value if isinstance(value, list) else []
        except (OSError, ValueError):
            return []

    def _save_push_subscriptions(self):
        tmp = self.push_file.with_suffix(".tmp")
        tmp.write_text(json.dumps(self.push_subscriptions, indent=2) + "\n")
        tmp.chmod(0o600)
        tmp.replace(self.push_file)

    def _ensure_vapid_key(self):
        if self.vapid_file.exists():
            return
        private = ec.generate_private_key(ec.SECP256R1())
        self.vapid_file.write_bytes(private.private_bytes(
            serialization.Encoding.PEM, serialization.PrivateFormat.PKCS8,
            serialization.NoEncryption(),
        ))
        self.vapid_file.chmod(0o600)

    def vapid_public_key(self):
        private = serialization.load_pem_private_key(self.vapid_file.read_bytes(), password=None)
        return b64e(private.public_key().public_bytes(
            serialization.Encoding.X962, serialization.PublicFormat.UncompressedPoint,
        ))

    def add_push_subscription(self, subscription):
        if not isinstance(subscription, dict) or not isinstance(subscription.get("endpoint"), str):
            raise ValueError("invalid push subscription")
        keys = subscription.get("keys", {})
        if not all(isinstance(keys.get(key), str) for key in ("p256dh", "auth")):
            raise ValueError("push subscription keys are missing")
        self.push_subscriptions = [s for s in self.push_subscriptions if s.get("endpoint") != subscription["endpoint"]]
        self.push_subscriptions.append(subscription)
        self._save_push_subscriptions()

    def notify(self, request: Request):
        if not self.push_subscriptions:
            return
        from pywebpush import WebPushException, webpush
        payload = json.dumps({
            "title": "Codex approval requested",
            "body": f"{request.operation} on {request.target}",
            "url": self.origin + "/?request=" + request.id,
            "tag": request.id,
        })
        active = []
        for subscription in self.push_subscriptions:
            try:
                webpush(
                    subscription_info=subscription, data=payload,
                    vapid_private_key=str(self.vapid_file),
                    vapid_claims={"sub":self.vapid_subject},
                    timeout=10,
                )
                active.append(subscription)
            except WebPushException as exc:
                status = getattr(getattr(exc, "response", None), "status_code", None)
                if status not in (404, 410):
                    active.append(subscription)
            except Exception:
                active.append(subscription)
        if len(active) != len(self.push_subscriptions):
            self.push_subscriptions = active
            self._save_push_subscriptions()

    def challenge(self, purpose: str, request_id: str | None = None) -> tuple[str, bytes]:
        random_part = secrets.token_bytes(32)
        if request_id is not None:
            request = self.requests.get(request_id)
            if request is None or request.state != "pending":
                raise ValueError("request is not pending")
            value = request.digest + struct.pack(">Q", int(time.time())) + random_part[:24]
        else:
            value = random_part
        ceremony_id = secrets.token_urlsafe(18)
        self.challenges[ceremony_id] = (purpose, value, time.time() + 60, request_id)
        return ceremony_id, value

    def consume_challenge(self, ceremony_id: str, purpose: str) -> tuple[bytes, str | None]:
        item = self.challenges.pop(ceremony_id, None)
        if item is None or item[0] != purpose or item[2] < time.time():
            raise ValueError("challenge is missing or expired")
        return item[1], item[3]

    def execute(self, request: Request):
        if request.operation != "demo.echo":
            request.state = "denied"
            request.result = {"error": "operation has no policy handler"}
            return
        message = request.parameters.get("message")
        if not isinstance(message, str) or len(message) > 500:
            request.state = "denied"
            request.result = {"error": "message must be a string of at most 500 characters"}
            return
        request.state = "completed"
        request.result = {"message": message}

    def deny(self, request: Request):
        if request.state != "pending":
            raise ValueError("request is not pending")
        request.state = "denied"
        request.result = {"ok": False, "error": "denied by owner"}

    def _executor(self, payload: dict, socket_timeout: int = 305):
        encoded = json.dumps(payload, separators=(",", ":")).encode() + b"\n"
        if len(encoded) > 65_536:
            raise ValueError("executor request is too large")
        with socket.socket(socket.AF_UNIX, socket.SOCK_STREAM) as client:
            client.settimeout(socket_timeout)
            client.connect("/run/codex-approval/executor.sock")
            client.sendall(encoded)
            response = b""
            while not response.endswith(b"\n") and len(response) <= 1_048_576:
                chunk = client.recv(65_536)
                if not chunk:
                    break
                response += chunk
        return json.loads(response)

    def execute_privileged(self, request: Request, challenge: bytes, assertion: dict):
        operation_timeout = request.parameters.get("timeout", 300)
        socket_timeout = min(operation_timeout + 5, 21_605) if isinstance(operation_timeout, int) else 305
        result = self._executor({"request": request.signed_payload(), "challenge": b64e(challenge), "assertion": assertion}, socket_timeout)
        lease_id = result.pop("lease_id", None)
        if result.get("ok") and lease_id and request.task_id:
            key = (request.target, request.task_id)
            self.leases[key] = lease_id
            self.lease_expiries[key] = result["expires_at"]
            self._save_leases()
        request.state = "completed" if result.get("ok") else "denied"
        request.result = result

    def try_execute_leased(self, request: Request) -> bool:
        if not request.task_id:
            return False
        key = (request.target, request.task_id)
        lease_id = self.leases.get(key)
        if not lease_id:
            return False
        operation_timeout = request.parameters.get("timeout", 300)
        socket_timeout = min(operation_timeout + 5, 21_605) if isinstance(operation_timeout, int) else 305
        result = self._executor({"request": request.signed_payload(), "lease_id": lease_id}, socket_timeout)
        if result.pop("lease_miss", False):
            return False
        if result.pop("lease_invalid", False):
            self.leases.pop(key, None)
            self.lease_expiries.pop(key, None)
            self._save_leases()
            return False
        request.state = "completed" if result.get("ok") else "denied"
        request.result = result
        return True


class Handler(BaseHTTPRequestHandler):
    server_version = "CodexApproval/0.1"

    @property
    def broker(self) -> Broker:
        return self.server.broker  # type: ignore[attr-defined]

    def log_message(self, fmt, *args):
        print(f"{self.address_string()} {fmt % args}")

    def send_json(self, status: int, value):
        body = json.dumps(value, separators=(",", ":")).encode()
        self.send_response(status)
        self.send_header("Content-Type", "application/json")
        self.send_header("Content-Length", str(len(body)))
        self.send_header("Cache-Control", "no-store")
        self.send_header("X-Content-Type-Options", "nosniff")
        self.end_headers()
        self.wfile.write(body)

    def read_json(self):
        length = int(self.headers.get("Content-Length", "0"))
        if length > 32_768:
            raise ValueError("request body is too large")
        return json.loads(self.rfile.read(length))

    def client_scope(self) -> ClientScope | None:
        supplied = self.headers.get("Authorization", "").removeprefix("Bearer ")
        return self.broker.client_scope(supplied)

    def do_GET(self):
        path = urlparse(self.path).path
        if path == "/":
            body = (Path(__file__).parent / "static" / "index.html").read_bytes()
            self.send_response(200)
            self.send_header("Content-Type", "text/html; charset=utf-8")
            self.send_header("Content-Length", str(len(body)))
            self.send_header("Cache-Control", "no-store")
            self.send_header("Content-Security-Policy", "default-src 'self'; script-src 'self'; style-src 'self'; connect-src 'self'; frame-ancestors 'none'")
            self.end_headers()
            self.wfile.write(body)
        elif path in {"/app.js", "/sw.js", "/styles.css", "/manifest.webmanifest"}:
            filename = path.removeprefix("/")
            body = (Path(__file__).parent / "static" / filename).read_bytes()
            self.send_response(200)
            if filename.endswith("webmanifest"):
                content_type = "application/manifest+json"
            elif filename.endswith("css"):
                content_type = "text/css; charset=utf-8"
            else:
                content_type = "text/javascript; charset=utf-8"
            self.send_header("Content-Type", content_type)
            self.send_header("Content-Length", str(len(body)))
            self.send_header("Cache-Control", "no-store")
            self.end_headers()
            self.wfile.write(body)
        elif path == "/api/status":
            self.send_json(200, {"enrolled": self.broker.credential is not None, "rpId": self.broker.rp_id, "pushSubscriptions":len(self.broker.push_subscriptions)})
        elif path == "/api/push/key":
            self.send_json(200, {"publicKey":self.broker.vapid_public_key()})
        elif path == "/api/requests":
            with self.broker.lock:
                pending = [r.public() for r in self.broker.requests.values() if r.state == "pending"]
            self.send_json(200, pending)
        elif path.startswith("/api/request/"):
            scope = self.client_scope()
            if scope is None:
                self.send_json(401, {"error": "unauthorized"})
                return
            request = self.broker.requests.get(path.rsplit("/", 1)[-1])
            if request is not None and request.target != scope.target:
                self.send_json(404, {"error": "not found"})
                return
            self.send_json(200 if request else 404, request.public() if request else {"error": "not found"})
        else:
            self.send_json(404, {"error": "not found"})

    def do_POST(self):
        path = urlparse(self.path).path
        try:
            body = self.read_json()
            with self.broker.lock:
                if path == "/api/client/requests":
                    scope = self.client_scope()
                    if scope is None:
                        self.send_json(401, {"error": "unauthorized"})
                        return
                    operation = body["operation"]
                    if not isinstance(operation, str) or not scope.allows(operation):
                        self.send_json(403, {"error": "operation is outside this client's scope"})
                        return
                    if operation == "approval.batch":
                        items = body.get("parameters", {}).get("requests")
                        if not isinstance(items, list) or any(
                            not isinstance(item, dict) or not scope.allows(item.get("operation", ""))
                            for item in items
                        ):
                            self.send_json(403, {"error":"batch contains an operation outside this client's scope"})
                            return
                    request = Request(
                        operation=operation,
                        parameters=body.get("parameters", {}),
                        requester=body.get("requester", "codex"),
                        host=body.get("host", "unknown"),
                        target=scope.target,
                        task_id=body.get("taskId"),
                    )
                    if not isinstance(request.operation, str) or not isinstance(request.parameters, dict):
                        raise ValueError("invalid request")
                    if request.task_id is not None and (not isinstance(request.task_id, str) or not TASK_ID.fullmatch(request.task_id)):
                        raise ValueError("taskId must be 8-128 URL-safe characters")
                    if request.operation in {"container.command.lease", "command.lease", "approval.batch"} and request.task_id is None:
                        raise ValueError("a taskId is required for a lease or batch")
                    self.broker.requests[request.id] = request
                    leased = False
                    if request.operation not in {"container.command.lease", "command.lease", "approval.batch"} and request.task_id:
                        request.state = "executing"
                        self.broker.lock.release()
                        try:
                            leased = self.broker.try_execute_leased(request)
                        finally:
                            self.broker.lock.acquire()
                        if not leased:
                            request.state = "pending"
                    self.send_json(201, request.public())
                    if not leased:
                        threading.Thread(target=self.broker.notify, args=(request,), daemon=True).start()
                elif path == "/api/register/options":
                    if self.broker.credential is not None:
                        raise ValueError("a credential is already enrolled")
                    supplied = body.get("enrollmentToken", "")
                    if not supplied or not hmac.compare_digest(supplied, self.broker.enrollment_token):
                        self.send_json(401, {"error": "invalid enrollment code"})
                        return
                    ceremony_id, challenge = self.broker.challenge("register")
                    self.send_json(200, {
                        "ceremonyId": ceremony_id,
                        "challenge": b64e(challenge), "rp": {"name": "Codex Approval", "id": self.broker.rp_id},
                        "user": {"id": b64e(secrets.token_bytes(16)), "name": "owner", "displayName": "Device owner"},
                        "pubKeyCredParams": [{"type": "public-key", "alg": -7}],
                        "authenticatorSelection": {"residentKey": "preferred", "userVerification": "required"},
                        "attestation": "none", "timeout": 60000,
                    })
                elif path == "/api/register/verify":
                    challenge, _ = self.broker.consume_challenge(body["ceremonyId"], "register")
                    credential = credential_from_registration(body["credential"], challenge, self.broker.origin, self.broker.rp_id)
                    self.broker.save_credential(credential)
                    self.broker.enrollment_token = secrets.token_urlsafe(32)
                    self.send_json(200, {"ok": True})
                elif path == "/api/approve/options":
                    if self.broker.credential is None:
                        raise ValueError("no credential is enrolled")
                    request_id = body["requestId"]
                    ceremony_id, challenge = self.broker.challenge("approve", request_id)
                    self.send_json(200, {
                        "ceremonyId": ceremony_id,
                        "challenge": b64e(challenge), "rpId": self.broker.rp_id,
                        "allowCredentials": [{"type": "public-key", "id": self.broker.credential.id}],
                        "userVerification": "required", "timeout": 60000,
                    })
                elif path == "/api/deny/options":
                    if self.broker.credential is None:
                        raise ValueError("no credential is enrolled")
                    request_id = body["requestId"]
                    ceremony_id, challenge = self.broker.challenge("deny", request_id)
                    self.send_json(200, {
                        "ceremonyId": ceremony_id,
                        "challenge": b64e(challenge), "rpId": self.broker.rp_id,
                        "allowCredentials": [{"type": "public-key", "id": self.broker.credential.id}],
                        "userVerification": "required", "timeout": 60000,
                    })
                elif path == "/api/push/options":
                    if self.broker.credential is None:
                        raise ValueError("no credential is enrolled")
                    ceremony_id, challenge = self.broker.challenge("push")
                    self.send_json(200, {
                        "ceremonyId":ceremony_id, "challenge":b64e(challenge), "rpId":self.broker.rp_id,
                        "allowCredentials":[{"type":"public-key", "id":self.broker.credential.id}],
                        "userVerification":"required", "timeout":60000,
                    })
                elif path == "/api/push/subscribe":
                    if self.broker.credential is None:
                        raise ValueError("no credential is enrolled")
                    challenge, _ = self.broker.consume_challenge(body["ceremonyId"], "push")
                    verify_assertion(body["assertion"], self.broker.credential, challenge, self.broker.origin, self.broker.rp_id)
                    self.broker.add_push_subscription(body["subscription"])
                    self.send_json(200, {"ok":True})
                elif path == "/api/approve/verify":
                    if self.broker.credential is None:
                        raise ValueError("no credential is enrolled")
                    challenge, request_id = self.broker.consume_challenge(body["ceremonyId"], "approve")
                    if body.get("requestId") != request_id:
                        raise ValueError("approval request ID does not match")
                    count = verify_assertion(body["assertion"], self.broker.credential, challenge, self.broker.origin, self.broker.rp_id)
                    self.broker.credential.sign_count = count
                    self.broker.save_credential(self.broker.credential)
                    request = self.broker.requests[request_id]
                    if request.state != "pending":
                        raise ValueError("request is not pending")
                    if request.operation == "demo.echo":
                        self.broker.execute(request)
                    else:
                        request.state = "executing"
                        self.broker.lock.release()
                        try:
                            self.broker.execute_privileged(request, challenge, body["assertion"])
                        except Exception as exc:
                            request.state = "denied"
                            request.result = {"ok":False, "error":f"executor failed: {type(exc).__name__}"}
                            raise
                        finally:
                            self.broker.lock.acquire()
                    self.send_json(200, request.public())
                elif path == "/api/deny/verify":
                    if self.broker.credential is None:
                        raise ValueError("no credential is enrolled")
                    challenge, request_id = self.broker.consume_challenge(body["ceremonyId"], "deny")
                    if body.get("requestId") != request_id:
                        raise ValueError("denial request ID does not match")
                    count = verify_assertion(body["assertion"], self.broker.credential, challenge, self.broker.origin, self.broker.rp_id)
                    self.broker.credential.sign_count = count
                    self.broker.save_credential(self.broker.credential)
                    request = self.broker.requests[request_id]
                    self.broker.deny(request)
                    self.send_json(200, request.public())
                else:
                    self.send_json(404, {"error": "not found"})
        except (KeyError, TypeError, ValueError, json.JSONDecodeError) as exc:
            self.send_json(HTTPStatus.BAD_REQUEST, {"error": str(exc)})
        except Exception as exc:
            self.send_json(HTTPStatus.BAD_REQUEST, {"error": f"verification failed: {type(exc).__name__}"})


def parser():
    result = argparse.ArgumentParser()
    result.add_argument("--listen", default="127.0.0.1")
    result.add_argument("--port", type=int, default=8787)
    result.add_argument("--origin", default="http://localhost:8787")
    result.add_argument("--rp-id", default="localhost")
    result.add_argument("--data-dir", type=Path, default=Path("data"))
    token = result.add_mutually_exclusive_group(required=True)
    token.add_argument("--client-token")
    token.add_argument("--client-token-file", type=Path)
    result.add_argument("--scoped-client-token-file", action="append", default=[], metavar="TARGET=PATH")
    result.add_argument("--vapid-subject", default="mailto:admin@example.com", help="Web Push contact URI, normally a mailto: address")
    result.add_argument("--enrollment-token", help="one-time phone enrollment code; generated when omitted")
    return result


def main():
    args = parser().parse_args()
    if args.client_token:
        client_token = args.client_token
    elif args.client_token_file.exists():
        client_token = args.client_token_file.read_text().strip()
    else:
        args.client_token_file.parent.mkdir(parents=True, exist_ok=True)
        client_token = secrets.token_urlsafe(32)
        args.client_token_file.write_text(client_token + "\n")
        args.client_token_file.chmod(0o600)
    if len(client_token) < 9:
        raise SystemExit("client token must be at least 9 characters")
    scoped_client_tokens = {}
    for item in args.scoped_client_token_file:
        target, separator, raw_path = item.partition("=")
        if not separator or not target or not raw_path:
            raise SystemExit("--scoped-client-token-file must be TARGET=PATH")
        if not TARGET_NAME.fullmatch(target):
            raise SystemExit("scoped client target has an invalid name")
        token_path = Path(raw_path)
        if token_path.exists():
            scoped_token = token_path.read_text().strip()
        else:
            token_path.parent.mkdir(parents=True, exist_ok=True)
            scoped_token = secrets.token_urlsafe(32)
            token_path.write_text(scoped_token + "\n")
            token_path.chmod(0o600)
        if len(scoped_token) < 9 or scoped_token == client_token or scoped_token in scoped_client_tokens:
            raise SystemExit("scoped client tokens must be unique and at least 9 characters")
        scoped_client_tokens[scoped_token] = ClientScope(target, frozenset({"container.admin.command", "container.command.lease", "approval.batch"}))
    enrollment_token = args.enrollment_token or secrets.token_urlsafe(18)
    broker = Broker(args.data_dir, args.origin, args.rp_id, client_token, enrollment_token, scoped_client_tokens, args.vapid_subject)
    server = ThreadingHTTPServer((args.listen, args.port), Handler)
    server.broker = broker
    print(f"Approval UI: {args.origin} (RP ID: {args.rp_id})")
    if args.client_token_file:
        print(f"Client token file: {args.client_token_file}")
    if broker.credential is None:
        print(f"One-time enrollment code: {enrollment_token}")
    server.serve_forever()


if __name__ == "__main__":
    main()
