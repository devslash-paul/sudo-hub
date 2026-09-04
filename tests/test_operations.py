from pathlib import Path
import os

import pytest

from sudo_hub.operations import PolicyError, build_plan, build_target_plan


def test_lifecycle_is_structured():
    plan = build_plan("proxmox.guest.lifecycle", {"kind":"vm", "action":"reboot", "vmid":101})
    assert plan.argv == ("/usr/sbin/qm", "reboot", "101")
    with pytest.raises(PolicyError):
        build_plan("proxmox.guest.lifecycle", {"kind":"vm", "action":"exec", "vmid":"101;id"})


def test_lxc_mount_restricts_source_roots():
    plan = build_plan("proxmox.lxc.mount", {"action":"set", "vmid":112, "slot":2, "source":"/base/media", "target":"/media"})
    assert plan.argv[-2:] == ("--mp2", "/base/media,mp=/media")
    with pytest.raises(PolicyError, match="allowed host roots"):
        build_plan("proxmox.lxc.mount", {"action":"set", "vmid":112, "slot":2, "source":"/etc", "target":"/host"})


def test_mount_requires_fstab_entry(tmp_path: Path):
    fstab = tmp_path / "fstab"
    fstab.write_text("server:/data /mnt/data nfs defaults 0 0\n")
    assert build_plan("maintenance.mount.fstab", {"action":"mount", "target":"/mnt/data"}, fstab=fstab).argv == ("/usr/bin/mount", "/mnt/data")
    with pytest.raises(PolicyError, match="fstab"):
        build_plan("maintenance.mount.fstab", {"action":"mount", "target":"/mnt/other"}, fstab=fstab)


def test_generic_admin_command_accepts_exact_system_argv():
    owner = os.stat("/usr/bin/id").st_uid
    plan = build_plan("admin.command", {"argv":["/usr/bin/id"]}, root_uid=owner)
    assert plan.argv == ("/usr/bin/id",)
    assert plan.destructive


@pytest.mark.parametrize("executable", ["bash", "/bin/sh", "/usr/bin/python3", "./systemctl"])
def test_generic_admin_command_blocks_shells_and_relative_paths(executable):
    with pytest.raises(PolicyError):
        build_plan("admin.command", {"argv":[executable, "anything"]})


def test_container_admin_command_is_bound_to_configured_target():
    plan = build_target_plan(
        "container.admin.command",
        {"argv":["/usr/bin/apt-get", "update"], "timeout":120},
        target="spoke",
        container_targets={"spoke":"123"},
    )
    assert plan.argv == ("/usr/sbin/pct", "exec", "123", "--", "/usr/bin/apt-get", "update")
    assert "spoke (LXC 123)" in plan.summary
    with pytest.raises(PolicyError, match="allowed guest"):
        build_target_plan(
            "container.admin.command", {"argv":["/usr/bin/id"]},
            target="host", container_targets={"spoke":"123"},
        )


def test_guest_admin_command_supports_typed_lxc_and_qemu_targets():
    lxc = build_target_plan(
        "guest.admin.command", {"argv":["/usr/bin/id"]},
        target="web", guest_targets={"web":"lxc:123"},
    )
    assert lxc.argv == ("/usr/sbin/pct", "exec", "123", "--", "/usr/bin/id")
    assert lxc.result_format == "process"

    qemu = build_target_plan(
        "guest.admin.command", {"argv":["/usr/bin/id"], "timeout":120},
        target="database", guest_targets={"database":"qemu:220"},
    )
    assert qemu.argv == (
        "/usr/sbin/qm", "guest", "exec", "220", "--timeout", "120", "--",
        "/usr/bin/id",
    )
    assert qemu.result_format == "qemu-guest-agent"
    assert "database (QEMU VM 220)" in qemu.summary


@pytest.mark.parametrize("spec", ["vm:220", "qemu:99", "lxc:not-a-vmid", "qemu:220:extra"])
def test_guest_admin_command_rejects_invalid_target_specs(spec):
    with pytest.raises(PolicyError, match="lxc:VMID or qemu:VMID"):
        build_target_plan(
            "guest.admin.command", {"argv":["/usr/bin/id"]},
            target="spoke", guest_targets={"spoke":spec},
        )


def test_container_scope_cannot_invoke_host_operation():
    with pytest.raises(PolicyError, match="not allowed for this target"):
        build_target_plan(
            "admin.command", {"argv":["/usr/bin/id"]},
            target="spoke", container_targets={"spoke":"123"},
        )


@pytest.mark.parametrize("executable", ["/bin/sh", "/usr/bin/python3", "apt-get", "/opt/tool"])
def test_container_admin_blocks_shells_and_non_system_paths(executable):
    with pytest.raises(PolicyError):
        build_target_plan(
            "container.admin.command", {"argv":[executable]},
            target="spoke", container_targets={"spoke":"123"},
        )
