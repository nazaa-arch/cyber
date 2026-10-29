"""Mesin Adaptif (Bab 9.2 dan 9.3): berbasis aturan dan skor, bukan RL.

d* = argmax_d [ V(d) - lambda * R(d) ]   dengan   sum R <= B
Kedalaman naik hanya bila sinyal tahap mendukung dan anggaran masih ada.
Bila penyerang menguji konsistensi, kedalaman dibekukan.
"""
from __future__ import annotations

from dataclasses import dataclass, field

# Skala ordinal (Bab 9.3): rendah=1, sedang=2, tinggi=3.
# level: (V nilai intelijen, R risiko terbongkar)
DEPTH_TABLE = {
    1: (1, 1),  # banner dan register dasar
    2: (2, 1),  # register tambahan dan halaman HMI
    3: (3, 2),  # efek perintah tulis palsu
    4: (3, 3),  # berkas konfigurasi dan honeytoken
}

STAGE_TO_DEPTH = {
    "reconnaissance": 1,
    "enumeration": 2,
    "manipulation_attempt": 3,
    "persistence": 4,
}


@dataclass
class AdaptiveEngine:
    risk_budget: float = 7.0   # B
    caution: float = 0.5       # lambda
    depth: int = 1
    spent: float = field(default=DEPTH_TABLE[1][1])
    frozen: bool = False
    high_tier: bool = False

    def net_value(self, d: int) -> float:
        v, r = DEPTH_TABLE[d]
        return v - self.caution * r

    def observe_consistency_probe(self) -> None:
        """Pola menguji konsistensi: bekukan kedalaman, tandai penyerang tingkat tinggi."""
        self.frozen = True
        self.high_tier = True

    def update(self, stage: str) -> int:
        target = STAGE_TO_DEPTH.get(stage, self.depth)
        if self.frozen or target <= self.depth:
            return self.depth
        # naik satu level per langkah, selama nilai bersih positif dan anggaran cukup
        nxt = self.depth + 1
        if nxt > target:
            return self.depth
        _, r = DEPTH_TABLE[nxt]
        if self.net_value(nxt) > 0 and self.spent + r <= self.risk_budget:
            self.depth = nxt
            self.spent += r
        return self.depth

    def settle(self, stage: str) -> int:
        """Naikkan kedalaman langkah demi langkah sampai stabil untuk tahap ini."""
        while True:
            before = self.depth
            self.update(stage)
            if self.depth == before:
                return self.depth
