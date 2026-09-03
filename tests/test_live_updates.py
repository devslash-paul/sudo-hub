from pathlib import Path


def test_approval_app_polls_without_interrupting_active_ceremony():
    app = Path("src/codex_approval/static/app.js").read_text()
    assert "setInterval(refreshIfChanged,2000)" in app
    assert "document.visibilityState !== 'visible'" in app
    assert "approvalBusy" in app
