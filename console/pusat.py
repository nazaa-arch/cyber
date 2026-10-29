"""Pusat komando: menerima ringkasan dari satuan, korelasi lintas satuan (Bab 9.6, 11)."""
from __future__ import annotations

import time
from collections import deque
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
        self.events_log: deque = deque(maxlen=200)

    def register_unit(self, satuan: str, lat: float, lon: float, level: str = "KODIM",
                      role: str = "", commander: str = "", comm_link: str = "",
                      asset_name: str = "") -> None:
        self.units[satuan] = {
            "satuan": satuan,
            "lat": lat,
            "lon": lon,
            "level": level,
            "role": role or f"Satuan Teritorial Operasi ({level})",
            "commander": commander or "Komandan Satuan Taktis",
            "comm_link": comm_link or "Radio Taktis VHF/HF + Satelit VSAT Militer",
            "asset_name": asset_name or "Sistem Kendali Industri SCADA/PLC Taktis",
            "registered_at": time.time(),
        }

    def receive(self, blob: bytes) -> None:
        """Titik masuk transport Edge Sync."""
        summary = edge_sync.decode(blob)
        self.received += 1
        self.received_bytes += len(blob)
        self.corr.add(summary)
        self.campaign_list = self.corr.campaigns()

        # Catat ke events log untuk timeline real-time
        self.events_log.appendleft({
            "ts": time.time(),
            "satuan": summary.get("satuan", "Pusat"),
            "session": summary.get("session", "N/A"),
            "src": summary.get("src", "N/A"),
            "stage": summary.get("stage", "reconnaissance"),
            "techniques": summary.get("techniques", []),
            "diverted": summary.get("diverted", False),
        })

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
        out = []
        for u in self.units.values():
            st = self.status(u["satuan"])
            # Hitung total sentuhan/sesi
            touches = sum(1 for k in self.corr.sessions if k[0] == u["satuan"])
            out.append({
                **u,
                "status": st,
                "touches": touches,
            })
        return out

    def get_campaign_vectors(self) -> list[dict]:
        """Menghasilkan koordinat garis vektor serangan antar satuan untuk visualisasi peta."""
        vectors = []
        for c in self.campaign_list:
            order = c.get("urutan_sentuh", [])
            for i in range(len(order) - 1):
                s1_name = order[i]["satuan"]
                s2_name = order[i + 1]["satuan"]
                if s1_name in self.units and s2_name in self.units:
                    u1 = self.units[s1_name]
                    u2 = self.units[s2_name]
                    vectors.append({
                        "campaign_id": c["id"],
                        "from_satuan": s1_name,
                        "to_satuan": s2_name,
                        "from_lat": u1["lat"],
                        "from_lon": u1["lon"],
                        "to_lat": u2["lat"],
                        "to_lon": u2["lon"],
                        "bukti": c.get("bukti", "korelasi"),
                        "waktu": order[i + 1].get("first_wall", time.time())
                    })
        return vectors


class Link:
    """Saklar link satuan-pusat (untuk uji ketahanan putus jaringan)."""

    def __init__(self, pusat: Pusat):
        self.pusat = pusat
        self.up = True

    def __call__(self, blob: bytes) -> None:
        if not self.up:
            raise ConnectionError("link ke pusat terputus")
        self.pusat.receive(blob)
