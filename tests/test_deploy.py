from pathlib import Path


def test_executor_runtime_directory_is_traversable():
    unit = Path("deploy/codex-approval-executor.service").read_text()
    assert "RuntimeDirectory=codex-approval" in unit
    assert "RuntimeDirectoryMode=0755" in unit


def test_executor_does_not_hide_kernel_modules_from_package_maintenance():
    unit = Path("deploy/codex-approval-executor.service").read_text()
    assert "ProtectKernelModules=true" not in unit


def test_units_load_topology_from_one_external_environment_file():
    broker = Path("deploy/codex-approval.service").read_text()
    executor = Path("deploy/codex-approval-executor.service").read_text()
    expected = "EnvironmentFile=/etc/sudo-hub/sudo-hub.env"
    assert expected in broker
    assert expected in executor
    assert "${SPOKE_TOKEN_SPEC}" in broker
    assert "${SPOKE_TARGET_SPEC}" in executor


def test_public_environment_example_contains_no_private_topology():
    example = Path("deploy/sudo-hub.env.example").read_text()
    assert "approve.example.com" in example
    assert "SPOKE_TOKEN_SPEC=spoke=" in example
    assert "SPOKE_TARGET_SPEC=spoke=123" in example
