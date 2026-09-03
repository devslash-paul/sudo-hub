from __future__ import annotations

import base64
import hashlib
import json
import struct
from dataclasses import dataclass

from cryptography.hazmat.primitives import hashes
from cryptography.hazmat.primitives.asymmetric import ec


def b64e(value: bytes) -> str:
    return base64.urlsafe_b64encode(value).rstrip(b"=").decode()


def b64d(value: str) -> bytes:
    return base64.urlsafe_b64decode(value + "=" * (-len(value) % 4))


class CborError(ValueError):
    pass


def _read_uint(data: bytes, pos: int, additional: int) -> tuple[int, int]:
    if additional < 24:
        return additional, pos
    sizes = {24: 1, 25: 2, 26: 4, 27: 8}
    size = sizes.get(additional)
    if size is None or pos + size > len(data):
        raise CborError("unsupported or truncated CBOR integer")
    return int.from_bytes(data[pos : pos + size], "big"), pos + size


def decode_cbor(data: bytes, pos: int = 0):
    if pos >= len(data):
        raise CborError("truncated CBOR")
    initial = data[pos]
    pos += 1
    major, additional = initial >> 5, initial & 31
    size, pos = _read_uint(data, pos, additional)
    if major == 0:
        return size, pos
    if major == 1:
        return -1 - size, pos
    if major in (2, 3):
        end = pos + size
        if end > len(data):
            raise CborError("truncated CBOR string")
        value = data[pos:end]
        return (value if major == 2 else value.decode()), end
    if major == 4:
        result = []
        for _ in range(size):
            value, pos = decode_cbor(data, pos)
            result.append(value)
        return result, pos
    if major == 5:
        result = {}
        for _ in range(size):
            key, pos = decode_cbor(data, pos)
            value, pos = decode_cbor(data, pos)
            result[key] = value
        return result, pos
    raise CborError(f"unsupported CBOR major type {major}")


@dataclass
class Credential:
    id: str
    x: str
    y: str
    sign_count: int = 0

    @property
    def public_key(self):
        numbers = ec.EllipticCurvePublicNumbers(
            int.from_bytes(b64d(self.x), "big"),
            int.from_bytes(b64d(self.y), "big"),
            ec.SECP256R1(),
        )
        return numbers.public_key()


def parse_authenticator_data(data: bytes, rp_id: str, require_attested: bool = False):
    if len(data) < 37:
        raise ValueError("authenticator data is too short")
    if data[:32] != hashlib.sha256(rp_id.encode()).digest():
        raise ValueError("relying-party ID hash does not match")
    flags = data[32]
    if not flags & 0x01:
        raise ValueError("user presence is required")
    if not flags & 0x04:
        raise ValueError("user verification is required")
    sign_count = struct.unpack(">I", data[33:37])[0]
    if require_attested and not flags & 0x40:
        raise ValueError("attested credential data is missing")
    return flags, sign_count


def verify_client_data(encoded: str, expected_type: str, challenge: bytes, origin: str) -> bytes:
    raw = b64d(encoded)
    value = json.loads(raw)
    if value.get("type") != expected_type:
        raise ValueError("unexpected WebAuthn ceremony type")
    if value.get("challenge") != b64e(challenge):
        raise ValueError("challenge does not match")
    if value.get("origin") != origin:
        raise ValueError("origin does not match")
    if value.get("crossOrigin", False):
        raise ValueError("cross-origin assertions are not accepted")
    return raw


def credential_from_registration(response: dict, challenge: bytes, origin: str, rp_id: str) -> Credential:
    client_raw = verify_client_data(response["clientDataJSON"], "webauthn.create", challenge, origin)
    attestation, end = decode_cbor(b64d(response["attestationObject"]))
    if end != len(b64d(response["attestationObject"])) or not isinstance(attestation, dict):
        raise ValueError("invalid attestation object")
    auth_data = attestation.get("authData")
    if not isinstance(auth_data, bytes):
        raise ValueError("attestation has no authenticator data")
    _, sign_count = parse_authenticator_data(auth_data, rp_id, require_attested=True)
    pos = 37 + 16
    if pos + 2 > len(auth_data):
        raise ValueError("truncated credential data")
    credential_len = int.from_bytes(auth_data[pos : pos + 2], "big")
    pos += 2
    credential_id = auth_data[pos : pos + credential_len]
    pos += credential_len
    cose, _ = decode_cbor(auth_data, pos)
    if cose.get(1) != 2 or cose.get(3) != -7 or cose.get(-1) != 1:
        raise ValueError("only ES256 P-256 credentials are supported")
    if b64e(credential_id) != response["id"]:
        raise ValueError("credential ID does not match attestation")
    # Parsing client data above is the ceremony binding. Attestation format "none"
    # intentionally supplies no manufacturer trust statement.
    _ = client_raw
    return Credential(response["id"], b64e(cose[-2]), b64e(cose[-3]), sign_count)


def verify_assertion(response: dict, credential: Credential, challenge: bytes, origin: str, rp_id: str) -> int:
    if response.get("id") != credential.id:
        raise ValueError("credential is not registered")
    client_raw = verify_client_data(response["clientDataJSON"], "webauthn.get", challenge, origin)
    auth_data = b64d(response["authenticatorData"])
    _, sign_count = parse_authenticator_data(auth_data, rp_id)
    signature = b64d(response["signature"])
    credential.public_key.verify(signature, auth_data + hashlib.sha256(client_raw).digest(), ec.ECDSA(hashes.SHA256()))
    if credential.sign_count and sign_count and sign_count <= credential.sign_count:
        raise ValueError("authenticator signature counter did not increase")
    return sign_count
