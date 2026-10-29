"""Log Berantai-Hash SHA-256 (Bab 6.2, 6.3, 14): bukti tak terubah."""
from __future__ import annotations

import hashlib
import json

GENESIS = "0" * 64


def _digest(event: dict, prev_hash: str) -> str:
    body = {k: v for k, v in event.items() if k not in ("hash", "prev_hash")}
    payload = prev_hash + json.dumps(body, sort_keys=True, separators=(",", ":"))
    return hashlib.sha256(payload.encode()).hexdigest()


class HashChain:
    def __init__(self):
        self.events: list[dict] = []

    def append(self, event: dict) -> dict:
        prev = self.events[-1]["hash"] if self.events else GENESIS
        ev = dict(event)
        ev["event_id"] = ev.get("event_id") or f"evt-{len(self.events) + 1:06d}"
        ev["prev_hash"] = prev
        ev["hash"] = _digest(ev, prev)
        self.events.append(ev)
        return ev

    def verify(self) -> bool:
        prev = GENESIS
        for ev in self.events:
            if ev["prev_hash"] != prev or ev["hash"] != _digest(ev, prev):
                return False
            prev = ev["hash"]
        return True
