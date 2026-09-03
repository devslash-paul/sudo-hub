from pathlib import Path
import time

import pytest

from codex_approval.model import Request
from codex_approval.server import Broker, ClientScope


def test_challenge_is_bound_to_request_and_single_use(tmp_path: Path):
    broker = Broker(tmp_path, "https://approve.test", "approve.test", "client-token", "enroll-token")
    request = Request("demo.echo", {"message": "hello"}, "codex", "host")
    broker.requests[request.id] = request
    ceremony_id, challenge = broker.challenge("approve", request.id)
    assert challenge[:32] == request.digest
    assert broker.consume_challenge(ceremony_id, "approve") == (challenge, request.id)
    with pytest.raises(ValueError, match="missing or expired"):
        broker.consume_challenge(ceremony_id, "approve")


def test_executor_allows_only_typed_demo_operation(tmp_path: Path):
    broker = Broker(tmp_path, "https://approve.test", "approve.test", "client-token", "enroll-token")
    denied = Request("shell", {"command": "id"}, "codex", "host")
    broker.execute(denied)
    assert denied.state == "denied"
    allowed = Request("demo.echo", {"message": "hello"}, "codex", "host")
    broker.execute(allowed)
    assert allowed.state == "completed"


def test_owner_can_deny_pending_request(tmp_path: Path):
    broker = Broker(tmp_path, "https://approve.test", "approve.test", "client-token", "enroll-token")
    request = Request("demo.echo", {"message": "hello"}, "codex", "host")
    broker.requests[request.id] = request
    broker.deny(request)
    assert request.state == "denied"
    assert request.result == {"ok": False, "error": "denied by owner"}
    with pytest.raises(ValueError, match="not pending"):
        broker.deny(request)


def test_client_tokens_have_distinct_server_side_scopes(tmp_path: Path):
    broker = Broker(
        tmp_path, "https://approve.test", "approve.test", "host-token", "enroll-token",
        {"container-token":ClientScope("spoke", frozenset({"container.admin.command"}))},
    )
    host = broker.client_scope("host-token")
    container = broker.client_scope("container-token")
    assert host.target == "host" and host.allows("admin.command")
    assert container.target == "spoke"
    assert container.allows("container.admin.command")
    assert not container.allows("admin.command")
    assert not container.allows("admin.command")
    assert broker.client_scope("wrong-token") is None


def test_broker_reuses_only_matching_task_lease(tmp_path: Path, monkeypatch):
    broker = Broker(tmp_path, "https://approve.test", "approve.test", "host-token", "enroll-token")
    broker.leases[("spoke", "task_123456")] = "opaque-lease"
    seen = []
    monkeypatch.setattr(broker, "_executor", lambda payload, socket_timeout=305: seen.append((payload, socket_timeout)) or {"ok":True, "output":"ok"})
    request = Request("container.admin.command", {"argv":["/usr/bin/id"]}, "codex", "code", target="spoke", task_id="task_123456")
    assert broker.try_execute_leased(request)
    assert seen[0][0]["lease_id"] == "opaque-lease"
    assert request.state == "completed"
    other = Request("container.admin.command", {"argv":["/usr/bin/id"]}, "codex", "code", target="spoke", task_id="other_123456")
    assert not broker.try_execute_leased(other)


def test_batch_miss_keeps_lease_for_later_matching_command(tmp_path: Path, monkeypatch):
    broker = Broker(tmp_path, "https://approve.test", "approve.test", "host-token", "enroll-token")
    key = ("host", "task_123456")
    broker.leases[key] = "opaque-lease"
    monkeypatch.setattr(broker, "_executor", lambda payload, socket_timeout=305: {
        "ok":False, "lease_miss":True, "error":"not a member"
    })
    request = Request("admin.command", {"argv":["/usr/bin/id"]}, "codex", "host", task_id="task_123456")
    assert not broker.try_execute_leased(request)
    assert broker.leases[key] == "opaque-lease"


def test_broker_restores_unexpired_lease_mapping_after_restart(tmp_path: Path):
    broker = Broker(tmp_path, "https://approve.test", "approve.test", "host-token", "enroll-token")
    key = ("host", "task_123456")
    broker.leases[key] = "opaque-lease"
    broker.lease_expiries[key] = int(time.time()) + 60
    broker._save_leases()

    restarted = Broker(tmp_path, "https://approve.test", "approve.test", "host-token", "enroll-token")
    assert restarted.leases[key] == "opaque-lease"
