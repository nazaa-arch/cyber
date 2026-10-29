"""Bayangan Sosial (Bab 10): persona fiktif, honeydoc, frasa kanari, kontak kanari.

Semua persona dan dokumen 100% fiktif; tidak ada data personel nyata. Modul ini
hanya mencatat dan melaporkan; tidak pernah membalas atau berinteraksi ofensif.
Penempatan umpan harus disetujui komandan satuan dan ditinjau secara hukum.
"""
from __future__ import annotations

import hashlib
import os
import random
import re
import time

from engine.gamelan import Gamelan

_FIRST = ["Rakai", "Sarwa", "Tirta", "Wening", "Lintang", "Gandra", "Bayu", "Kusuma"]
_LAST = ["Anggara", "Mahendra", "Prawira", "Santika", "Wibisana", "Kartana", "Danuarta"]
_ROLES = ["Kepala Seksi Logistik", "Staf Administrasi", "Operator Depo", "Teknisi Jaringan",
          "Kepala Urusan Dalam"]
_WORDS = ["senja", "garuda", "teratai", "mahkota", "bentala", "cakra", "samudra", "pelita"]
DEFAULT_DOMAIN = "satuan-demo.invalid"   # TLD .invalid: bawaan untuk pengujian air-gapped


class SocialDecoys:
    def __init__(self, satuan: str, seed: int, secret: bytes, bus: Gamelan | None = None,
                 domain: str | None = None):
        self.satuan = satuan
        self.rng = random.Random(seed)
        self.secret = secret
        self.bus = bus
        self.domain = domain or os.environ.get("DECOY_DOMAIN") or DEFAULT_DOMAIN
        self.personas: dict[str, dict] = {}
        self.canaries: dict[str, str] = {}       # frasa -> id dokumen
        self.contacts: dict[str, str] = {}       # nomor/akun -> id
        self.hits: list[dict] = []

    def _tag(self, *parts: str) -> str:
        return hashlib.sha256(self.secret + "|".join(parts).encode()).hexdigest()[:6]

    def make_directory(self, n: int = 5) -> list[dict]:
        out = []
        for i in range(n):
            nama = f"{self.rng.choice(_FIRST)} {self.rng.choice(_LAST)}"
            tag = self._tag(self.satuan, nama, str(i))
            email = f"{nama.lower().replace(' ', '.')}.{tag}@{self.domain}"
            p = {"nama": nama, "jabatan": self.rng.choice(_ROLES), "email": email, "fiktif": True}
            self.personas[email] = p
            out.append(p)
        return out

    def make_honeydoc(self, doc_id: str) -> dict:
        phrase = "-".join(self.rng.sample(_WORDS, 3)) + "-" + self._tag(doc_id)
        self.canaries[phrase] = doc_id
        text = (f"NOTA DINAS (FIKTIF) {doc_id}\nPerihal: jadwal pengisian depo\n"
                f"Kode referensi: {phrase}\n")
        return {"id": doc_id, "frasa_kanari": phrase, "isi": text}

    def make_canary_contact(self, label: str) -> str:
        num = f"+62-800-{self._tag(label, 'tel')}"
        self.contacts[num] = label
        return num

    # ---- sinyal masuk ----
    def _hit(self, kind: str, ident: str, **extra) -> dict:
        h = {"ts": time.time(), "kind": kind, "id": ident, "satuan": self.satuan, **extra}
        self.hits.append(h)
        if self.bus is not None:
            self.bus.publish({
                "ts": time.strftime("%Y-%m-%dT%H:%M:%SZ", time.gmtime()),
                "t_mono": time.monotonic(), "satuan": self.satuan, "shadow": "sosial",
                "proto": "social", "src": extra.get("src", "unknown"),
                "session": f"sos-{ident}", "action": kind, "target": {"id": ident},
                "stage": "reconnaissance", "depth": 0, "via": "social"})
        return h

    def on_mail(self, rcpt: str, sender: str, subject: str = "") -> dict | None:
        if rcpt in self.personas:
            return self._hit("decoy_email_received", rcpt, src=sender, subject=subject[:80])
        return None

    def scan_text(self, text: str, src: str = "gateway", where: str = "") -> list[dict]:
        """Cari frasa kanari di teks yang terlihat keluar lewat gateway/tempat tak semestinya."""
        out = []
        for phrase, doc in self.canaries.items():
            if re.search(re.escape(phrase), text):
                out.append(self._hit("canary_phrase_seen", doc, src=src, where=where))
        return out

    def on_call(self, number: str, caller: str) -> dict | None:
        if number in self.contacts:
            return self._hit("canary_contact_touched", self.contacts[number], src=caller)
        return None

    def recon_map(self) -> list[dict]:
        """Peta Pengintaian: persona/dokumen mana yang tersentuh lebih dulu."""
        return sorted(self.hits, key=lambda h: h["ts"])
