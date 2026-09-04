import os
from pathlib import Path


def test_executor_runtime_directory_is_traversable():
    unit = Path("deploy/sudo-hub-executor.service").read_text()
    assert "RuntimeDirectory=sudo-hub" in unit
    assert "RuntimeDirectoryMode=0755" in unit


def test_executor_does_not_hide_kernel_modules_from_package_maintenance():
    unit = Path("deploy/sudo-hub-executor.service").read_text()
    assert "ProtectKernelModules=true" not in unit


def test_units_use_the_hub_environment_and_managed_virtualenv():
    broker = Path("deploy/sudo-hub.service").read_text()
    executor = Path("deploy/sudo-hub-executor.service").read_text()
    expected = "EnvironmentFile=/etc/sudo-hub/hub.env"
    assert expected in broker
    assert expected in executor
    assert "/opt/sudo-hub/.venv/bin/sudo-hub-server" in broker
    assert "/opt/sudo-hub/.venv/bin/sudo-hub-executor" in executor
    assert "/usr/bin/python3" not in executor
    assert "${SPOKE_TOKEN_SPEC}" in broker
    assert "--guest-target ${SPOKE_TARGET_SPEC}" in broker
    assert "${SPOKE_TARGET_SPEC}" in executor
    assert "--guest-target ${SPOKE_TARGET_SPEC}" in executor


def test_public_environment_examples_contain_no_private_topology():
    hub = Path("deploy/hub.env.example").read_text()
    spoke = Path("deploy/spoke.env.example").read_text()
    assert "approve.example.com" in hub
    assert "SPOKE_TOKEN_SPEC=spoke=" in hub
    assert "SPOKE_TARGET_SPEC=spoke=lxc:123" in hub
    assert "qemu:VMID" in hub
    assert "approve.example.com" in spoke
    assert "SUDO_HUB_CLIENT_USER=automation" in spoke


def test_hub_and_spoke_installers_are_executable():
    for name in ("install-hub.sh", "install-hub-credential.sh", "install-spoke.sh", "sudo-hub-spoke-request"):
        path = Path("deploy") / name
        assert path.is_file()
        assert os.access(path, os.X_OK)
