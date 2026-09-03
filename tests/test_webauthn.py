import hashlib
import json
import struct

import pytest

from codex_approval.webauthn import b64e, decode_cbor, parse_authenticator_data, verify_client_data


def test_decode_small_cbor_map():
    value, end = decode_cbor(bytes.fromhex("a201022004"))
    assert value == {1: 2, -1: 4}
    assert end == 5


def test_client_data_binds_challenge_and_origin():
    challenge = b"challenge"
    raw = json.dumps({"type":"webauthn.get", "challenge":b64e(challenge), "origin":"https://approve.test"}).encode()
    assert verify_client_data(b64e(raw), "webauthn.get", challenge, "https://approve.test") == raw
    with pytest.raises(ValueError, match="origin"):
        verify_client_data(b64e(raw), "webauthn.get", challenge, "https://wrong.test")


def test_authenticator_data_requires_uv():
    rp_id = "approve.test"
    without_uv = hashlib.sha256(rp_id.encode()).digest() + b"\x01" + struct.pack(">I", 0)
    with pytest.raises(ValueError, match="verification"):
        parse_authenticator_data(without_uv, rp_id)
