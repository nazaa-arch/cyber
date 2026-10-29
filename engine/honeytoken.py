"""Honeytoken unik per sesi dan satuan (Bab 9.2 persistensi, Bab 12)."""
from __future__ import annotations

import hashlib
import hmac
import re

TOKEN_RE = re.compile(r"^HT[0-9a-f]{12}$")


def make_token(secret: bytes, satuan: str, session_id: str) -> str:
    mac = hmac.new(secret, f"{satuan}|{session_id}".encode(), hashlib.sha256)
    return "HT" + mac.hexdigest()[:12]


def looks_like_token(s: str) -> bool:
    return bool(TOKEN_RE.match(s or ""))
