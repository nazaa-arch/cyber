"""Pipeline analisis: Gamelan -> pemeta ATT&CK -> log berantai-hash -> penyimpan sesi
-> generator aturan -> Bot Dalang -> Edge Sync (Bab 6.1, 9.5).
"""
from __future__ import annotations

import time

from engine.approval import ApprovalQueue
from engine.attck_map import AttckMapper
from engine.autonomy import Autonomy
from engine.fingerprint import build_fingerprint
from evidence.hashchain import HashChain
from evidence.session_store import SessionStore
from kelir.session import SessionRegistry

INFO_ALERT_DEDUP_S = 60.0     # deduplikasi per sumber (Bab 14.1, banjir alert)


class Pipeline:
    def __init__(self, satuan: str, sessions: SessionRegistry, store: SessionStore,
                 chain: HashChain, mapper: AttckMapper, autonomy: Autonomy,
                 approvals: ApprovalQueue, bot=None, edge=None):
        self.satuan = satuan
        self.sessions = sessions
        self.store = store
        self.chain = chain
        self.mapper = mapper
        self.autonomy = autonomy
        self.approvals = approvals
        self.bot = bot
        self.edge = edge
        self.alerts: list[dict] = []
        self._last_info: dict[str, float] = {}
        self.technique_counts: dict[str, int] = {}

    # ---------- ringkasan sesi ----------
    def summary(self, s) -> dict:
        evs = self.store.events(s.id)
        return {
            "satuan": self.satuan, "session": s.id, "src": s.src,
            "first_wall": s.first_wall, "last_wall": time.time(),
            "stage": s.stage, "depth": s.engine.depth, "diverted": s.diverted,
            "high_tier": s.engine.high_tier, "event_count": len(evs),
            "techniques": sorted(s.techniques),
            "fingerprint": build_fingerprint(s.actions, s.proto_features),
            "honeytokens_planted": sorted(s.honeytokens_planted),
            "honeytokens_used": sorted(s.honeytokens_used),
            "default_cred": s.default_cred,
            "write_targets": [{"table": t, "addr": a} for _, t, a, _v in s.writes],
            "chain_head": self.chain.events[-1]["hash"] if self.chain.events else None,
        }

    # ---------- penanganan kejadian ----------
    def on_event(self, ev: dict) -> None:
        s = self.sessions.by_id.get(ev.get("session"))
        ev["attack_technique"] = self.mapper.map(ev)
        rec = self.chain.append(ev)
        ev.update(rec)                                    # event_id, prev_hash, hash
        self.store.add_event(ev)
        for t in ev["attack_technique"]:
            self.technique_counts[t] = self.technique_counts.get(t, 0) + 1
        if ev.get("action") == "ids_flag":                 # tanda dari Suricata (tanpa sesi)
            self._alert("ids", ev, f"Suricata menandai {ev.get('src')}: "
                        f"{ev.get('ids_signature')} (sid {ev.get('ids_sid')}). "
                        "Sumber ini akan dilayani bayangan bila menyentuh aset OT.",
                        warn=int(ev.get("ids_severity") or 3) <= 1)
        if s is None:
            return
        s.techniques.update(ev["attack_technique"])
        if ev.get("honeytoken_planted"):
            s.honeytokens_planted.add(ev["honeytoken_planted"])
        if ev.get("honeytoken_used"):
            s.honeytokens_used.add(ev["honeytoken_used"])

        action = ev["action"]
        summ = self.summary(s)
        self.store.put_session(summ)
        if action == "shadow_divert":
            self._on_divert(ev, s, summ)
        elif action == "honeytoken_used" or action == "http_login_honeytoken":
            self._alert("honeytoken", ev, f"Honeytoken dipakai dari {s.src}: "
                        f"{ev.get('honeytoken_used')}", warn=True)
        elif action == "would_divert":
            self._alert("rekomendasi", ev, f"Rekomendasi (L{self.autonomy.level}): "
                        f"sesi {s.src} layak dialihkan. {ev.get('reason', '')}")
        elif action == "diverted_write_alert":
            self._on_diverted_write(ev, s, summ)
        elif action == "ids_flag_operator":
            tindak = ("dikarantina ke bayangan" if ev.get("ids_mode") == "divert"
                      else "masih ke aset asli, butuh keputusan Dalang")
            self._alert("ids_operator", ev, f"PERINGATAN: operator terdaftar {s.src} "
                        f"ditandai Suricata ({ev.get('ids_signature')}); sesi {tindak}.",
                        warn=True)
        elif action not in ("auto_block",) and not s.pinned and s.events <= 1:
            self._info(ev, s)
        if self.edge is not None and (s.diverted or s.honeytokens_planted
                                      or s.honeytokens_used or s.events % 5 == 0):
            self.edge.enqueue(summ)

    def _info(self, ev, s) -> None:
        last = self._last_info.get(s.src, -1e9)
        if ev["t_mono"] - last < INFO_ALERT_DEDUP_S:
            return
        self._last_info[s.src] = ev["t_mono"]
        self._alert("info", ev, f"Sentuhan pertama pada bayangan {ev.get('shadow')} dari {s.src}")

    def _on_divert(self, ev, s, summ) -> None:
        prop = self.approvals.propose(summ) if self.autonomy.can_draft else None
        self._alert("divert", ev, ev.get("reason", ""), warn=True)
        if self.bot:
            self.bot.notify_divert(summ, prop, ev.get("reason", ""))
        if self.edge is not None:
            self.edge.enqueue(summ)

    def _on_diverted_write(self, ev: dict, s, summ: dict) -> None:
        msg = (f"PERINGATAN OPERATOR: Perintah tulis dari {s.src} "
               f"(Unit:{ev.get('unit')}, FC:{ev.get('fc')}, Addr:{ev.get('addr')}, Val:{ev.get('val')}) "
               f"dialihkan ke bayangan (PLC fisik aman).")
        self._alert("diverted_write", ev, msg, warn=True)
        if self.bot:
            if hasattr(self.bot, "notify_diverted_write"):
                self.bot.notify_diverted_write(
                    s.src, ev.get("unit", 1), ev.get("fc", 0), ev.get("addr"), ev.get("val"), ev.get("reason", "")
                )
            else:
                self.bot.info(msg)

    def _alert(self, kind: str, ev: dict, text: str, warn: bool = False) -> None:
        self.alerts.append({"kind": kind, "session": ev.get("session"), "text": text,
                            "t_event": ev["t_mono"], "t_alert": time.monotonic(),
                            "warn": warn, "event_id": ev.get("event_id")})
        if self.bot and kind in ("info", "honeytoken", "rekomendasi", "ids", "ids_operator"):
            self.bot.info(text)

    # ---------- bukti ----------
    def verify_chain(self) -> bool:
        return self.chain.verify()

    def heatmap(self) -> dict[str, dict]:
        return {t: {"count": c, "name": self.mapper.name(t), "tactic": self.mapper.tactic(t)}
                for t, c in sorted(self.technique_counts.items())}
