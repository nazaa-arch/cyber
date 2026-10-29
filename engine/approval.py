"""Antrean persetujuan Dalang untuk draf aturan dan blokir (Bab 9.5, 11, 11.1, 14.1).

* Draf aturan selalu menunggu persetujuan manusia sebelum diterapkan.
* Kontribusi satu sumber dibatasi (mitigasi peracunan data, Bab 14.1).
* Setiap keputusan punya masa berlaku dan dapat dibatalkan.
"""
from __future__ import annotations

import json
import pathlib
import time
from dataclasses import dataclass, field

from engine import rulegen
from engine.autonomy import Blocklist

MAX_PROPOSALS_PER_SOURCE = 3
APPROVED_BLOCK_TTL_S = 24 * 3600.0


@dataclass
class Proposal:
    id: str
    session: str
    satuan: str
    src: str
    bundle: dict
    status: str = "pending"        # pending | approved | ignored
    created: float = field(default_factory=time.time)
    decided_by: str | None = None
    decided_at: float | None = None
    files: dict = field(default_factory=dict)

    def brief(self) -> dict:
        return {"id": self.id, "session": self.session, "satuan": self.satuan,
                "src": self.src, "status": self.status, "created": self.created,
                "decided_by": self.decided_by, "hardening": self.bundle["hardening"],
                "ratio_benteng": self.bundle["ratio_benteng"], "files": self.files}


class ApprovalQueue:
    def __init__(self, out_dir: str | pathlib.Path, blocklist: Blocklist,
                 whitelist: set[str] | None = None, log=None,
                 lab_mode: bool = False):
        self.lab_mode = lab_mode      # uji lokal: izinkan sumber loopback
        self.out = pathlib.Path(out_dir)
        self.blocklist = blocklist
        self.whitelist = whitelist or set()
        self.items: dict[str, Proposal] = {}
        self.per_src: dict[str, int] = {}
        self.log = log or (lambda *a, **k: None)
        self._n = 0

    def propose(self, summary: dict) -> Proposal | None:
        src = summary["src"]
        if self.per_src.get(src, 0) >= MAX_PROPOSALS_PER_SOURCE:
            return None                               # batasi kontribusi satu sumber
        try:
            bundle = rulegen.build_bundle(summary, self.whitelist, self.lab_mode)
        except ValueError:
            return None                               # tidak layak (daftar putih/loopback)
        self.per_src[src] = self.per_src.get(src, 0) + 1
        self._n += 1
        p = Proposal(f"prp-{self._n:04d}", summary["session"], summary["satuan"], src, bundle)
        d = self.out / "rules" / summary["session"]
        d.mkdir(parents=True, exist_ok=True)
        (d / "deteksi_sigma.yml").write_text(bundle["sigma_yaml"], encoding="utf-8")
        (d / "ioc_stix.json").write_text(json.dumps(bundle["ioc"], indent=2), encoding="utf-8")
        (d / "blokir_draf.nft").write_text(bundle["nftables"], encoding="utf-8")
        p.files = {"sigma": str(d / "deteksi_sigma.yml"), "ioc": str(d / "ioc_stix.json"),
                   "nft_draft": str(d / "blokir_draf.nft")}
        self.items[p.id] = p
        return p

    def pending(self) -> list[Proposal]:
        return [p for p in self.items.values() if p.status == "pending"]

    def approve(self, pid: str, who: str = "dalang") -> Proposal:
        p = self.items[pid]
        if p.status != "pending":
            raise ValueError(f"proposal {pid} sudah {p.status}")
        applied = self.out / "applied"
        applied.mkdir(parents=True, exist_ok=True)
        (applied / f"{p.session}.nft").write_text(
            p.bundle["nftables"].replace("DRAF WAYANG - BELUM DITERAPKAN",
                                         f"DISETUJUI oleh {who}"), encoding="utf-8")
        self.blocklist.add(p.src, APPROVED_BLOCK_TTL_S, f"disetujui {who}: {p.id}", who)
        p.status, p.decided_by, p.decided_at = "approved", who, time.time()
        self.log("approve", p)
        return p

    def ignore(self, pid: str, who: str = "dalang") -> Proposal:
        p = self.items[pid]
        if p.status == "pending":
            p.status, p.decided_by, p.decided_at = "ignored", who, time.time()
            self.log("ignore", p)
        return p

    def revoke(self, pid: str, who: str = "dalang") -> Proposal:
        """Tombol batalkan: cabut blokir yang sudah disetujui."""
        p = self.items[pid]
        self.blocklist.cancel(p.src)
        p.status, p.decided_by, p.decided_at = "ignored", who, time.time()
        return p

