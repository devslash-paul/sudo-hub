from codex_approval.model import Request, canonical_json


def test_canonical_json_is_stable():
    assert canonical_json({"b": 1, "a": 2}) == b'{"a":2,"b":1}'


def test_request_digest_changes_with_parameters():
    first = Request("demo.echo", {"message": "one"}, "codex", "host", id="same", created_at=1)
    second = Request("demo.echo", {"message": "two"}, "codex", "host", id="same", created_at=1)
    assert first.digest != second.digest


def test_request_digest_is_bound_to_target():
    host = Request("admin.command", {"argv":["/usr/bin/id"]}, "codex", "host", target="host", id="same", created_at=1)
    container = Request("admin.command", {"argv":["/usr/bin/id"]}, "codex", "host", target="spoke", id="same", created_at=1)
    assert host.digest != container.digest
