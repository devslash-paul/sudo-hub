from __future__ import annotations

import hashlib
import json
import secrets
import time
from dataclasses import dataclass, field
from typing import Any


def canonical_json(value: Any) -> bytes:
    return json.dumps(value, sort_keys=True, separators=(",", ":"), ensure_ascii=False).encode()


@dataclass
class Request:
    operation: str
    parameters: dict[str, Any]
    requester: str
    host: str
    target: str = "host"
    task_id: str | None = None
    id: str = field(default_factory=lambda: secrets.token_urlsafe(18))
    created_at: int = field(default_factory=lambda: int(time.time()))
    state: str = "pending"
    result: dict[str, Any] | None = None

    def signed_payload(self) -> dict[str, Any]:
        value = {
            "id": self.id,
            "operation": self.operation,
            "parameters": self.parameters,
            "requester": self.requester,
            "host": self.host,
            "target": self.target,
            "created_at": self.created_at,
        }
        if self.task_id is not None:
            value["task_id"] = self.task_id
        return value

    @property
    def digest(self) -> bytes:
        return hashlib.sha256(canonical_json(self.signed_payload())).digest()

    def public(self) -> dict[str, Any]:
        value = self.signed_payload()
        value.update(state=self.state, result=self.result)
        return value
