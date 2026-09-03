from __future__ import annotations

import os
import re
import stat
from dataclasses import dataclass
from pathlib import Path
from typing import Any


class PolicyError(ValueError):
    pass


VMID = re.compile(r"^[1-9][0-9]{2,8}$")
UNIT = re.compile(r"^[A-Za-z0-9][A-Za-z0-9_.@:-]{0,127}(?:\.service)?$")
SNAPSHOT = re.compile(r"^[A-Za-z0-9][A-Za-z0-9_.-]{0,79}$")
STORAGE = re.compile(r"^[A-Za-z0-9][A-Za-z0-9_.-]{0,63}$")
BLOCKED_EXECUTABLES = {
    "sh", "bash", "dash", "zsh", "fish", "csh", "tcsh",
    "python", "python3", "perl", "ruby", "php", "lua", "node",
    "env", "sudo", "su", "doas", "pkexec", "chroot", "nsenter",
    "unshare", "xargs", "find", "vi", "vim", "nvim", "emacs",
}
LEASE_SAFE_EXECUTABLES = {
    "/usr/bin/id", "/usr/bin/uname", "/usr/bin/whoami", "/usr/bin/uptime",
    "/usr/bin/df", "/usr/bin/free", "/usr/bin/ls", "/usr/bin/lsblk",
    "/usr/bin/stat", "/usr/bin/readlink", "/usr/bin/realpath", "/usr/bin/ps",
    "/usr/bin/journalctl", "/usr/bin/mountpoint", "/usr/bin/test", "/usr/bin/true",
}
SYSTEMCTL_READ_ACTIONS = {"status", "show", "is-active", "is-enabled", "list-units", "list-unit-files"}
PCT_READ_ACTIONS = {"list", "status", "config"}


@dataclass(frozen=True)
class Plan:
    argv: tuple[str, ...]
    summary: str
    destructive: bool = False
    timeout: int = 300


def lease_command_is_read_only(parameters: dict[str, Any]) -> bool:
    argv = parameters.get("argv")
    if not isinstance(argv, list) or not argv or not all(isinstance(value, str) for value in argv):
        return False
    executable = argv[0]
    if executable in LEASE_SAFE_EXECUTABLES:
        return True
    if executable == "/usr/bin/systemctl":
        return len(argv) >= 2 and argv[1] in SYSTEMCTL_READ_ACTIONS
    if executable == "/usr/sbin/pct":
        return len(argv) >= 2 and argv[1] in PCT_READ_ACTIONS
    if executable == "/usr/sbin/pvesm":
        return len(argv) >= 2 and argv[1] == "status"
    if executable == "/usr/bin/pvesh":
        return len(argv) >= 2 and argv[1] in {"get", "usage"}
    return False


def _choice(value: Any, name: str, choices: set[str]) -> str:
    if value not in choices:
        raise PolicyError(f"{name} must be one of: {', '.join(sorted(choices))}")
    return value


def _vmid(value: Any) -> str:
    value = str(value)
    if not VMID.fullmatch(value):
        raise PolicyError("vmid must be an integer from 100 to 999999999")
    return value


def _path(value: Any, name: str) -> str:
    if not isinstance(value, str) or not value.startswith("/") or "\x00" in value:
        raise PolicyError(f"{name} must be an absolute path")
    normalized = os.path.normpath(value)
    if normalized != value or value == "/":
        raise PolicyError(f"{name} must be a normalized non-root path")
    return value


def _known_fstab_target(target: str, fstab: Path = Path("/etc/fstab")) -> bool:
    for raw in fstab.read_text().splitlines():
        line = raw.strip()
        if not line or line.startswith("#"):
            continue
        fields = line.split()
        if len(fields) >= 2 and fields[1].replace("\\040", " ") == target:
            return True
    return False


def build_plan(operation: str, p: dict[str, Any], *, fstab: Path = Path("/etc/fstab"), root_uid: int = 0) -> Plan:
    return build_target_plan(operation, p, fstab=fstab, root_uid=root_uid)


def _admin_argv(p: dict[str, Any], *, root_uid: int, inspect_executable: bool) -> tuple[list[str], int]:
    argv = p.get("argv")
    if not isinstance(argv, list) or not argv or len(argv) > 128 or not all(isinstance(v, str) for v in argv):
        raise PolicyError("argv must be a non-empty string array of at most 128 items")
    if any("\x00" in value or len(value) > 8192 for value in argv):
        raise PolicyError("argv contains an invalid or oversized value")
    executable = Path(argv[0])
    if (not executable.is_absolute() or executable.name in BLOCKED_EXECUTABLES
            or not str(executable).startswith(("/usr/bin/", "/usr/sbin/", "/bin/", "/sbin/"))):
        raise PolicyError("executable must be an allowed absolute system path")
    if inspect_executable:
        try:
            resolved = executable.resolve(strict=True)
            metadata = resolved.stat()
        except OSError as exc:
            raise PolicyError(f"cannot resolve executable: {exc}") from exc
        if not str(resolved).startswith(("/usr/bin/", "/usr/sbin/", "/bin/", "/sbin/")):
            raise PolicyError("executable is outside system program directories")
        if not stat.S_ISREG(metadata.st_mode) or metadata.st_uid != root_uid or metadata.st_mode & 0o022:
            raise PolicyError("executable must be a root-owned, non-writable regular file")
    timeout = p.get("timeout", 900)
    if not isinstance(timeout, int) or not 1 <= timeout <= 21_600:
        raise PolicyError("timeout must be between 1 and 21600 seconds")
    return argv, timeout


def build_target_plan(
    operation: str,
    p: dict[str, Any],
    *,
    target: str = "host",
    container_targets: dict[str, str] | None = None,
    fstab: Path = Path("/etc/fstab"),
    root_uid: int = 0,
) -> Plan:
    if operation == "container.admin.command":
        vmid = (container_targets or {}).get(target)
        if vmid is None or not VMID.fullmatch(vmid):
            raise PolicyError("target is not an allowed container")
        argv, timeout = _admin_argv(p, root_uid=root_uid, inspect_executable=False)
        command = ("/usr/sbin/pct", "exec", vmid, "--", *argv)
        return Plan(command, f"Run exact root command in {target} (LXC {vmid}): " + " ".join(argv), destructive=True, timeout=timeout)
    if target != "host":
        raise PolicyError("operation is not allowed for this target")
    if operation == "admin.command":
        argv, timeout = _admin_argv(p, root_uid=root_uid, inspect_executable=True)
        return Plan(tuple(argv), "Run exact root command: " + " ".join(argv), destructive=True, timeout=timeout)
    if operation == "maintenance.packages.refresh":
        return Plan(("/usr/bin/apt-get", "update"), "Refresh Debian package indexes", timeout=900)
    if operation == "maintenance.packages.upgrade":
        mode = _choice(p.get("mode", "safe"), "mode", {"safe", "full"})
        command = "upgrade" if mode == "safe" else "full-upgrade"
        return Plan(("/usr/bin/apt-get", "-y", command), f"Apply {mode} package upgrade", destructive=mode == "full", timeout=7200)
    if operation == "maintenance.service.control":
        unit, action = p.get("unit"), _choice(p.get("action"), "action", {"start", "stop", "restart", "reload"})
        if not isinstance(unit, str) or not UNIT.fullmatch(unit):
            raise PolicyError("invalid systemd unit name")
        if unit.removesuffix(".service") in {"codex-approval-executor", "tailscaled"} and action == "stop":
            raise PolicyError("policy prevents stopping the authorization path")
        return Plan(("/usr/bin/systemctl", action, unit), f"{action.title()} system service {unit}", destructive=action in {"stop", "restart"})
    if operation == "maintenance.mount.fstab":
        target = _path(p.get("target"), "target")
        action = _choice(p.get("action"), "action", {"mount", "unmount"})
        if not _known_fstab_target(target, fstab):
            raise PolicyError("target is not declared in /etc/fstab")
        argv = ("/usr/bin/mount", target) if action == "mount" else ("/usr/bin/umount", target)
        return Plan(argv, f"{action.title()} fstab target {target}", destructive=action == "unmount")
    if operation == "proxmox.guest.lifecycle":
        kind = _choice(p.get("kind"), "kind", {"lxc", "vm"})
        action = _choice(p.get("action"), "action", {"start", "shutdown", "reboot", "stop", "suspend", "resume"})
        vmid = _vmid(p.get("vmid"))
        tool = "/usr/sbin/pct" if kind == "lxc" else "/usr/sbin/qm"
        return Plan((tool, action, vmid), f"{action.title()} {kind.upper()} {vmid}", destructive=action in {"stop", "shutdown", "reboot", "suspend"}, timeout=900)
    if operation == "proxmox.guest.snapshot":
        kind = _choice(p.get("kind"), "kind", {"lxc", "vm"})
        action = _choice(p.get("action"), "action", {"create", "delete", "rollback"})
        vmid, name = _vmid(p.get("vmid")), p.get("name")
        if not isinstance(name, str) or not SNAPSHOT.fullmatch(name):
            raise PolicyError("invalid snapshot name")
        tool = "/usr/sbin/pct" if kind == "lxc" else "/usr/sbin/qm"
        verb = {"create": "snapshot", "delete": "delsnapshot", "rollback": "rollback"}[action]
        return Plan((tool, verb, vmid, name), f"{action.title()} snapshot {name} on {kind.upper()} {vmid}", destructive=action != "create", timeout=3600)
    if operation == "proxmox.guest.backup":
        vmid = _vmid(p.get("vmid"))
        mode = _choice(p.get("mode", "snapshot"), "mode", {"snapshot", "suspend", "stop"})
        argv = ["/usr/bin/vzdump", vmid, "--mode", mode]
        storage = p.get("storage")
        if storage is not None:
            if not isinstance(storage, str) or not STORAGE.fullmatch(storage):
                raise PolicyError("invalid storage ID")
            argv += ["--storage", storage]
        return Plan(tuple(argv), f"Back up guest {vmid} using {mode} mode", destructive=mode == "stop", timeout=21600)
    if operation == "proxmox.lxc.mount":
        vmid = _vmid(p.get("vmid"))
        slot = p.get("slot")
        if not isinstance(slot, int) or not 0 <= slot <= 255:
            raise PolicyError("slot must be an integer from 0 to 255")
        action = _choice(p.get("action"), "action", {"set", "remove"})
        key = f"mp{slot}"
        if action == "remove":
            return Plan(("/usr/sbin/pct", "set", vmid, f"--delete", key), f"Remove {key} from LXC {vmid}", destructive=True)
        source = _path(p.get("source"), "source")
        target = _path(p.get("target"), "target")
        if not source.startswith(("/mnt/", "/base/", "/plexbase/")):
            raise PolicyError("bind-mount source is outside allowed host roots")
        value = f"{source},mp={target}"
        if p.get("read_only", False):
            value += ",ro=1"
        return Plan(("/usr/sbin/pct", "set", vmid, f"--{key}", value), f"Set {key} on LXC {vmid}: {source} → {target}")
    raise PolicyError("operation has no privileged policy handler")
