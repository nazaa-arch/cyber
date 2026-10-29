"""Tingkat otonomi L0-L3, daftar blokir, dan saklar darurat (Bab 11.1).

L0 Amati | L1 Rekomendasi | L2 Pengalihan otomatis (bawaan) | L3 Blokir terbatas.
Tidak ada tindakan otomatis menyentuh aset asli selain meneruskan sesi sah.
"""
from __future__ import annotations

import time
from dataclasses import dataclass

LEVEL_NAMES = {0: "Amati", 1: "Rekomendasi", 2: "Pengalihan otomatis", 3: "Blokir terbatas"}
L3_REPEAT_THRESHOLD = 3          # sentuhan bayangan berulang sebelum blokir otomatis
L3_BLOCK_TTL_S = 900.0           # masa berlaku singkat


class Autonomy:
    def __init__(self, level: int = 2):
        assert 0 <= level <= 3
        self.level = level
        self.log: list[dict] = []

    def set_level(self, level: int, who: str = "dalang") -> None:
        assert 0 <= level <= 3
        self.log.append({"ts": time.time(), "from": self.level, "to": level, "who": who})
        self.level = level

    def kill_switch(self, who: str = "dalang") -> None:
        """Saklar darurat: kembalikan seluruh sistem ke L0."""
        self.set_level(0, who)

    @property
    def can_draft(self) -> bool:
        return self.level >= 1

    @property
    def can_divert(self) -> bool:
        return self.level >= 2

    @property
    def can_autoblock(self) -> bool:
        return self.level >= 3

    @property
    def name(self) -> str:
        return LEVEL_NAMES[self.level]


@dataclass
class BlockEntry:
    src: str
    expires: float
    reason: str
    by: str          # "dalang" atau "auto-L3"


class Blocklist:
    def __init__(self, clock=time.time):
        self.clock = clock
        self.entries: dict[str, BlockEntry] = {}

    def add(self, src: str, ttl_s: float, reason: str, by: str) -> BlockEntry:
        e = BlockEntry(src, self.clock() + ttl_s, reason, by)
        self.entries[src] = e
        return e

    def cancel(self, src: str) -> bool:
        return self.entries.pop(src, None) is not None

    def is_blocked(self, src: str) -> bool:
        e = self.entries.get(src)
        if e is None:
            return False
        if self.clock() >= e.expires:
            del self.entries[src]
            return False
        return True

    def active(self) -> list[BlockEntry]:
        return [e for s, e in list(self.entries.items()) if self.is_blocked(s)]
