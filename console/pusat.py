"""Pusat komando: menerima ringkasan dari satuan, korelasi lintas satuan (Bab 9.6, 11)."""
from __future__ import annotations

from console import edge_sync
from engine.fingerprint import Correlator


class Pusat:
    def __init__(self, correlator: Correlator | None = None, bot=None):
        self.corr = correlator or Correlator()
        self.bot = bot
        self.units: dict[str, dict] = {}
        self.received = 0
        self.received_bytes = 0
        self._known: set[str] = set()
        self.campaign_list: list[dict] = []

    def register_unit(self, satuan: str, lat: float, lon: float, level: str = "Kodim") -> None:
        self.units[satuan] = {"satuan": satuan, "lat": lat, "lon": lon, "level": level}

    def receive(self, blob: bytes) -> None:
        """Titik masuk transport Edge Sync."""
        summary = edge_sync.decode(blob)
        self.received += 1
        self.received_bytes += len(blob)
        self.corr.add(summary)
        self.campaign_list = self.corr.campaigns()
        for c in self.campaign_list:
            if c["id"] not in self._known:
                self._known.add(c["id"])
                if self.bot:
                    self.bot.notify_campaign(c)

    def status(self, satuan: str) -> str:
        for c in self.campaign_list:
            if satuan in c["satuan"]:
                return "Kampanye Terdeteksi"
        if any(k[0] == satuan for k in self.corr.sessions):
            return "Tipuan Disentuh"
        return "Aman"

    def map_state(self) -> list[dict]:
        return [{**u, "status": self.status(u["satuan"])} for u in self.units.values()]


class Link:
    """Saklar link satuan-pusat (untuk uji ketahanan putus jaringan)."""

    def __init__(self, pusat: Pusat):
        self.pusat = pusat
        self.up = True

    def __call__(self, blob: bytes) -> None:
        if not self.up:
            raise ConnectionError("link ke pusat terputus")
        self.pusat.receive(blob)
