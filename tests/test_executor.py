import hashlib
import json
import subprocess
import struct
import time
import pytest
import os

from cryptography.hazmat.primitives import hashes
from cryptography.hazmat.primitives.asymmetric import ec

from sudo_hub.executor import Executor, parse_guest_targets
from sudo_hub.model import Request
from sudo_hub.webauthn import b64e
from sudo_hub.operations import Plan, PolicyError


def test_guest_target_arguments_are_typed_and_legacy_lxc_is_preserved():
    assert parse_guest_targets(["database=qemu:220", "web=lxc:123"], []) == {
        "database":"qemu:220", "web":"lxc:123",
    }
    assert parse_guest_targets([], ["legacy=124"]) == {"legacy":"lxc:124"}
    with pytest.raises(PolicyError, match="configured more than once"):
        parse_guest_targets(["web=lxc:123"], ["web=124"])


def test_qemu_guest_agent_result_uses_guest_exit_status(monkeypatch):
    plan = Plan(
        ("/usr/sbin/qm", "guest", "exec", "220", "--timeout", "30", "--", "/usr/bin/id"),
        "Run command in VM", timeout=30, result_format="qemu-guest-agent",
    )
    completed = subprocess.CompletedProcess(
        plan.argv, 0,
        stdout=json.dumps({"exited":1, "exitcode":7, "out-data":"stdout\n", "err-data":"stderr\n"}),
        stderr="",
    )
    monkeypatch.setattr("sudo_hub.executor.subprocess.run", lambda *args, **kwargs: completed)

    result = Executor.execute_plan(plan)

    assert not result["ok"]
    assert result["exit_code"] == 7
    assert result["output"] == "stdout\nstderr\n"


def test_qemu_guest_agent_timeout_result_is_not_reported_as_success(monkeypatch):
    plan = Plan(
        ("/usr/sbin/qm", "guest", "exec", "220", "--", "/usr/bin/id"),
        "Run command in VM", timeout=30, result_format="qemu-guest-agent",
    )
    completed = subprocess.CompletedProcess(plan.argv, 0, stdout=json.dumps({"pid":42}), stderr="")
    monkeypatch.setattr("sudo_hub.executor.subprocess.run", lambda *args, **kwargs: completed)

    result = Executor.execute_plan(plan)

    assert not result["ok"]
    assert "did not finish" in result["error"]


def test_executor_independently_verifies_bound_assertion(tmp_path):
    origin, rp_id = "https://approve.test", "approve.test"
    private = ec.generate_private_key(ec.SECP256R1())
    numbers = private.public_key().public_numbers()
    credential = {
        "id": b64e(b"credential-id"),
        "x": b64e(numbers.x.to_bytes(32, "big")),
        "y": b64e(numbers.y.to_bytes(32, "big")),
        "sign_count": 0,
    }
    credential_file = tmp_path / "credential.json"
    credential_file.write_text(json.dumps(credential))
    request = Request("proxmox.guest.lifecycle", {"kind":"vm", "vmid":101, "action":"start"}, "agent", "host")
    challenge = request.digest + struct.pack(">Q", int(time.time())) + b"r" * 24
    client_data = json.dumps({"type":"webauthn.get", "challenge":b64e(challenge), "origin":origin}).encode()
    auth_data = hashlib.sha256(rp_id.encode()).digest() + b"\x05" + struct.pack(">I", 1)
    signature = private.sign(auth_data + hashlib.sha256(client_data).digest(), ec.ECDSA(hashes.SHA256()))
    assertion = {
        "id":credential["id"], "clientDataJSON":b64e(client_data),
        "authenticatorData":b64e(auth_data), "signature":b64e(signature),
    }
    executor = Executor(credential_file, origin, rp_id, tmp_path / "audit", 1000)
    verified_request, _, plan = executor.authorize({
        "request":request.signed_payload(), "challenge":b64e(challenge), "assertion":assertion,
    })
    assert verified_request.digest == request.digest
    assert plan.argv == ("/usr/sbin/qm", "start", "101")


def test_executor_routes_signed_container_target(tmp_path):
    origin, rp_id = "https://approve.test", "approve.test"
    private = ec.generate_private_key(ec.SECP256R1())
    numbers = private.public_key().public_numbers()
    credential = {
        "id": b64e(b"credential-id"),
        "x": b64e(numbers.x.to_bytes(32, "big")),
        "y": b64e(numbers.y.to_bytes(32, "big")),
        "sign_count": 0,
    }
    credential_file = tmp_path / "credential.json"
    credential_file.write_text(json.dumps(credential))
    request = Request(
        "container.admin.command", {"argv":["/usr/bin/id"]},
        "agent", "code", target="spoke", target_spec="lxc:123",
    )
    challenge = request.digest + struct.pack(">Q", int(time.time())) + b"r" * 24
    client_data = json.dumps({"type":"webauthn.get", "challenge":b64e(challenge), "origin":origin}).encode()
    auth_data = hashlib.sha256(rp_id.encode()).digest() + b"\x05" + struct.pack(">I", 1)
    signature = private.sign(auth_data + hashlib.sha256(client_data).digest(), ec.ECDSA(hashes.SHA256()))
    assertion = {
        "id":credential["id"], "clientDataJSON":b64e(client_data),
        "authenticatorData":b64e(auth_data), "signature":b64e(signature),
    }
    executor = Executor(
        credential_file, origin, rp_id, tmp_path / "audit", 1000,
        {"spoke":"123"},
    )
    _, _, plan = executor.authorize({
        "request":request.signed_payload(), "challenge":b64e(challenge), "assertion":assertion,
    })
    assert plan.argv == ("/usr/sbin/pct", "exec", "123", "--", "/usr/bin/id")


def test_container_lease_is_task_target_time_and_count_bound(tmp_path):
    executor = Executor(tmp_path / "credential", "https://approve.test", "approve.test", tmp_path / "audit", 1000, {"spoke":"123"})
    grant = Request("container.command.lease", {"duration":60, "max_commands":1, "group":"Inspect spoke", "goal":"Inspect container health without changing state"}, "agent", "code", target="spoke", task_id="task_123456", target_spec="lxc:123")
    issued = executor.grant_lease(grant)
    command = Request("container.admin.command", {"argv":["/usr/bin/id"]}, "agent", "code", target="spoke", task_id="task_123456", target_spec="lxc:123")

    _, plan, remaining, _ = executor.authorize_lease({"request":command.signed_payload(), "lease_id":issued["lease_id"]})
    assert plan.argv == ("/usr/sbin/pct", "exec", "123", "--", "/usr/bin/id")
    assert remaining == 0
    with pytest.raises(PolicyError, match="invalid, expired, exhausted"):
        executor.authorize_lease({"request":command.signed_payload(), "lease_id":issued["lease_id"]})


def test_container_lease_cannot_change_task_target_or_operation(tmp_path):
    executor = Executor(tmp_path / "credential", "https://approve.test", "approve.test", tmp_path / "audit", 1000, {"spoke":"123"})
    grant = Request("container.command.lease", {"duration":60, "max_commands":5, "group":"Inspect spoke", "goal":"Inspect container health without changing state"}, "agent", "code", target="spoke", task_id="task_123456", target_spec="lxc:123")
    lease_id = executor.grant_lease(grant)["lease_id"]
    for request in (
        Request("container.admin.command", {"argv":["/usr/bin/id"]}, "agent", "code", target="spoke", task_id="other_123456", target_spec="lxc:123"),
        Request("admin.command", {"argv":["/usr/bin/id"]}, "agent", "code", target="host", task_id="task_123456"),
    ):
        with pytest.raises(PolicyError, match="outside its task scope"):
            executor.authorize_lease({"request":request.signed_payload(), "lease_id":lease_id})


def test_container_lease_limits_are_narrow(tmp_path):
    executor = Executor(tmp_path / "credential", "https://approve.test", "approve.test", tmp_path / "audit", 1000, {"spoke":"123"})
    for parameters in ({"duration":301,"max_commands":1,"group":"Inspect spoke","goal":"Inspect container health without changing state"}, {"duration":60,"max_commands":51,"group":"Inspect spoke","goal":"Inspect container health without changing state"}):
        request = Request("container.command.lease", parameters, "agent", "code", target="spoke", task_id="task_123456", target_spec="lxc:123")
        with pytest.raises(PolicyError):
            executor.grant_lease(request)


def test_guest_lease_routes_qemu_target_and_checks_signed_binding(tmp_path):
    executor = Executor(
        tmp_path / "credential", "https://approve.test", "approve.test",
        tmp_path / "audit", 1000, guest_targets={"database":"qemu:220"},
    )
    grant = Request(
        "guest.command.lease",
        {"duration":60, "max_commands":2, "group":"Inspect database", "goal":"Inspect database VM health"},
        "agent", "code", target="database", task_id="task_123456", target_spec="qemu:220",
    )
    issued = executor.grant_lease(grant)
    command = Request(
        "guest.admin.command", {"argv":["/usr/bin/id"]}, "agent", "code",
        target="database", task_id="task_123456", target_spec="qemu:220",
    )

    _, plan, _, _ = executor.authorize_lease({
        "request":command.signed_payload(), "lease_id":issued["lease_id"],
    })

    assert plan.result_format == "qemu-guest-agent"
    assert plan.argv[:5] == ("/usr/sbin/qm", "guest", "exec", "220", "--timeout")

    changed_binding = Request(
        "guest.admin.command", {"argv":["/usr/bin/id"]}, "agent", "code",
        target="database", task_id="task_123456", target_spec="qemu:221",
    )
    with pytest.raises(PolicyError, match="bound to the configured guest"):
        executor.authorize_lease({
            "request":changed_binding.signed_payload(), "lease_id":issued["lease_id"],
        })


def test_unlisted_host_command_lease_is_task_time_and_count_bound(tmp_path):
    executor = Executor(tmp_path / "credential", "https://approve.test", "approve.test", tmp_path / "audit", 1000, root_uid=os.stat("/usr/bin/id").st_uid)
    grant = Request("command.lease", {"duration":120, "max_commands":10, "group":"Inspect host health", "goal":"Confirm host identity and kernel health without changes"}, "agent", "host", target="host", task_id="sudo_123456")
    issued = executor.grant_lease(grant)
    assert issued["max_commands"] == 10
    assert executor.leases[issued["lease_id"]]["operation"] == "admin.command"

    command = Request("admin.command", {"argv":["/usr/bin/id"]}, "agent", "host", target="host", task_id="sudo_123456")
    _, _, remaining, _ = executor.authorize_lease({"request":command.signed_payload(), "lease_id":issued["lease_id"]})
    assert remaining == 9
    wrong = Request("maintenance.packages.refresh", {}, "agent", "host", target="host", task_id="sudo_123456")
    with pytest.raises(PolicyError, match="outside this timed-sudo lease"):
        executor.authorize_lease({"request":wrong.signed_payload(), "lease_id":issued["lease_id"]})

    destructive = Request("admin.command", {"argv":["/usr/bin/rm","/tmp/example"]}, "agent", "host", target="host", task_id="sudo_123456")
    with pytest.raises(PolicyError, match="read-only"):
        executor.authorize_lease({"request":destructive.signed_payload(), "lease_id":issued["lease_id"]})


def test_executor_restores_unexpired_lease_after_restart(tmp_path):
    lease_file = tmp_path / "run" / "active-leases.json"
    executor = Executor(tmp_path / "credential", "https://approve.test", "approve.test",
                        tmp_path / "audit", 1000, root_uid=os.stat("/usr/bin/id").st_uid,
                        lease_file=lease_file)
    grant = Request("command.lease", {"duration":120, "max_commands":10,
                    "group":"Inspect host health",
                    "goal":"Confirm host identity and kernel health without changes"},
                    "agent", "host", target="host", task_id="sudo_123456")
    issued = executor.grant_lease(grant)

    restarted = Executor(tmp_path / "credential", "https://approve.test", "approve.test",
                         tmp_path / "audit", 1000, root_uid=os.stat("/usr/bin/id").st_uid,
                         lease_file=lease_file)
    assert restarted.leases[issued["lease_id"]]["remaining"] == 10


def test_command_lease_requires_named_group(tmp_path):
    executor = Executor(tmp_path / "credential", "https://approve.test", "approve.test", tmp_path / "audit", 1000)
    request = Request("command.lease", {"duration":60,"max_commands":5}, "agent", "host", task_id="sudo_123456")
    with pytest.raises(PolicyError, match="named task group"):
        executor.grant_lease(request)


def test_command_lease_requires_explained_goal(tmp_path):
    executor = Executor(tmp_path / "credential", "https://approve.test", "approve.test", tmp_path / "audit", 1000)
    request = Request("command.lease", {"duration":60,"max_commands":5,"group":"Inspect host"}, "agent", "host", task_id="sudo_123456")
    with pytest.raises(PolicyError, match="explain the bounded task"):
        executor.grant_lease(request)


def test_exact_batch_works_on_host_and_cannot_change_arguments(tmp_path):
    executor = Executor(tmp_path / "credential", "https://approve.test", "approve.test", tmp_path / "audit", 1000)
    command = {"operation":"maintenance.service.control", "parameters":{"unit":"example.service", "action":"restart"}}
    grant = Request("approval.batch", {"duration":60, "requests":[command]}, "agent", "host", target="host", task_id="batch_123456")
    lease_id = executor.grant_batch(grant)["lease_id"]
    exact = Request(command["operation"], command["parameters"], "agent", "host", target="host", task_id="batch_123456")
    _, plan, remaining, _ = executor.authorize_lease({"request":exact.signed_payload(), "lease_id":lease_id})
    assert plan.argv == ("/usr/bin/systemctl", "restart", "example.service")
    assert remaining == 0

    changed = Request("maintenance.service.control", {"unit":"other.service", "action":"restart"}, "agent", "host", target="host", task_id="batch_123456")
    with pytest.raises(PolicyError):
        executor.authorize_lease({"request":changed.signed_payload(), "lease_id":lease_id})


def test_batch_rejects_nested_or_invalid_operations(tmp_path):
    executor = Executor(tmp_path / "credential", "https://approve.test", "approve.test", tmp_path / "audit", 1000)
    for operation in ("approval.batch", "guest.command.lease", "container.command.lease", "command.lease"):
        grant = Request("approval.batch", {"duration":60, "requests":[{"operation":operation,"parameters":{}}]}, "agent", "host", task_id="batch_123456")
        with pytest.raises(PolicyError, match="nested"):
            executor.grant_batch(grant)
