"""WAYANG -> Wazuh: ekspor event bayangan sebagai JSON per baris.

Agen atau manajer Wazuh membaca berkas ini dengan:

    <localfile>
      <log_format>json</log_format>
      <location>/var/log/wayang/wayang-alerts.json</location>
    </localfile>

lalu rule di `integrations/wazuh/local_rules.xml` (id 100700-100719) mengubahnya
menjadi alert Wazuh lengkap dengan level dan teknik ATT&CK for ICS.

Kunci `srcip` sengaja ditaruh di tingkat atas agar Wazuh mengenalinya sebagai
alamat sumber (dipakai `same_source_ip` dan active response).
"""
from __future__ import annotations

import json
import os
import pathlib
import threading
import time

# Baca register mentah per transaksi terlalu ramai untuk SIEM; ringkasannya sudah
# terbawa event shadow_divert dan unlisted_source_read.
NOISY_ACTIONS = frozenset({
    "read_coils", "read_discrete_inputs", "read_holding_registers",
    "read_input_registers",
})

# Batas aman satu event Wazuh (analysisd memotong di 64 KiB).
MAX_LINE_BYTES = 60_000

_FIELDS = ("action", "session", "shadow", "proto", "stage", "depth", "via",
           "reason", "score", "unit", "fc", "addr", "val", "honeytoken_used",
           "honeytoken_planted", "ttl_s", "mirror_used", "event_id", "hash",
           "prev_hash", "ids_sid", "ids_signature", "ids_severity", "ids_mode")

_locks: dict[str, threading.Lock] = {}
_locks_guard = threading.Lock()


def _lock_for(path: str) -> threading.Lock:
    with _locks_guard:
        return _locks.setdefault(path, threading.Lock())


def to_wazuh_record(ev: dict, satuan: str) -> dict:
    """Ubah event Gamelan menjadi rekaman datar yang mudah dicocokkan rule Wazuh."""
    rec = {
        "timestamp": ev.get("ts") or time.strftime("%Y-%m-%dT%H:%M:%SZ", time.gmtime()),
        "integration": "wayang",
        "srcip": ev.get("src") or "",
        "wayang": {"satuan": ev.get("satuan") or satuan},
    }
    w = rec["wayang"]
    for k in _FIELDS:
        v = ev.get(k)
        if v is not None and v != "":
            w[k] = v
    techs = ev.get("attack_technique") or []
    if techs:
        w["mitre_ics"] = list(techs)
    sig = ev.get("signals")
    if isinstance(sig, dict):
        w["signals"] = {k: round(float(v), 3) for k, v in sig.items()
                        if isinstance(v, (int, float))}
    return rec


class WazuhExporter:
    """Pelanggan Gamelan; dipasang SETELAH Pipeline agar event sudah ber-hash."""

    def __init__(self, path: str, satuan: str, include_noisy: bool = False):
        self.path = str(pathlib.Path(path))
        self.satuan = satuan
        self.include_noisy = include_noisy
        self.written = 0
        self.errors = 0
        pathlib.Path(self.path).parent.mkdir(parents=True, exist_ok=True)
        self._lock = _lock_for(os.path.abspath(self.path))

    def __call__(self, ev: dict) -> None:
        if not self.include_noisy and ev.get("action") in NOISY_ACTIONS:
            return
        rec = to_wazuh_record(ev, self.satuan)
        line = json.dumps(rec, ensure_ascii=True, separators=(",", ":"), default=str)
        if len(line) > MAX_LINE_BYTES:
            rec["wayang"].pop("signals", None)
            rec["wayang"]["reason"] = str(rec["wayang"].get("reason", ""))[:500]
            rec["wayang"]["truncated"] = True
            line = json.dumps(rec, ensure_ascii=True, separators=(",", ":"), default=str)
        try:
            # Buka per tulis: aman terhadap logrotate dan tidak mengunci berkas di Windows.
            with self._lock, open(self.path, "a", encoding="ascii", newline="\n") as f:
                f.write(line + "\n")
            self.written += 1
        except OSError:
            self.errors += 1

    def status(self) -> dict:
        return {"path": self.path, "written": self.written, "errors": self.errors}
