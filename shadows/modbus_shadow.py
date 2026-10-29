"""Bayangan Modbus: meniru PLC/RTU dengan telemetri hidup (Bab 6.2, 8, 9.2, 9.4).

Semua perintah tulis berakhir log-only (Bab 9.2): tidak ada jalur tulis ke
aset asli dari modul ini.
"""
from __future__ import annotations

import asyncio
import math
import time
import zlib
from typing import Callable

import numpy as np

from engine.gamelan import Gamelan
from kelir.session import Session, SessionRegistry
from shadows import modbus_proto as mp
from telemetry.models import DepoBBMTelemetry

BLEND_S = 60.0            # lama "berpisah" dari nilai cermin ke jalur fiktif
PUMP_DELAY_S = (1.5, 3.0)  # jeda realistis efek perintah palsu
PUMP_TAU_S = 6.0
CONSISTENCY_PROBE_READS = 8


class LatencyProfile:
    """Latensi berekor panjang dengan emulasi PLC Scan Cycle (Bab 8, Lapisan Waktu).

    PLC industri nyata (Siemens S7, Schneider Modicon) memproses input-output
    mengikuti siklus scan ladder logic (umumnya 20ms-50ms). Paket yang tiba di tengah
    siklus dijadwalkan pada siklus scan berikutnya, menghasilkan pola sebaran waktu khas OT.
    """

    def __init__(self, seed: int, base_ms: float = 4.0, sigma: float = 0.5,
                 plc_scan_ms: float = 20.0):
        self.rng = np.random.default_rng(seed + 11)
        self.base_ms = base_ms
        self.sigma = sigma
        self.plc_scan_ms = plc_scan_ms

    def match(self, real_ms: float) -> None:
        """Samakan profil dengan aset asli (selisih latensi, Bab 9.4)."""
        self.base_ms = 0.8 * self.base_ms + 0.2 * max(1.0, min(real_ms, 40.0))

    def sample_s(self) -> float:
        # Komponen ekor panjang + emulasi quantized cycle time PLC
        ms = self.base_ms * float(self.rng.lognormal(0, self.sigma))
        cycle_phase = float(self.rng.uniform(0.3, 1.0)) * self.plc_scan_ms
        total_ms = max(ms, cycle_phase * 0.4) + float(abs(self.rng.normal(0, 0.3)))
        return min(total_ms, 400.0) / 1000.0


class ShadowDevice:
    def __init__(self, shadow_id: str, satuan: str, seed: int,
                 sessions: SessionRegistry, bus: Gamelan | None = None,
                 clock: Callable[[], float] = time.monotonic,
                 time_scale: float = 1.0, start_hour: float | None = None,
                 capacity_l: float = 20000.0, vendor: str = "Generik",
                 adaptive: bool = True):
        self.adaptive = adaptive      # False: bayangan statis (pembanding A/B, Bab 13)
        self.id = shadow_id
        self.satuan = satuan
        self.sessions = sessions
        self.bus = bus
        self.clock = clock
        self.scale = time_scale
        self.t0 = clock()
        lt = time.localtime()
        self.start_hour = (lt.tm_hour + lt.tm_min / 60.0) if start_hour is None else start_hour
        self.telemetry = DepoBBMTelemetry(seed, capacity_l)
        self.profile = LatencyProfile(seed)
        self._rng = np.random.default_rng(seed + 99)
        self._last_sim_h = 0.0
        self.values = {"tank_level_l": 0.0, "pump_pressure_bar": 1.8,
                       "flow_lph": 0.0, "temp_c": 27.0}
        self.idobj = {0: vendor, 1: f"GX-{100 + seed % 50}",
                      2: f"V{2 + seed % 3}.{seed % 7}.{seed % 5}"}
        for _ in range(30):                      # pemanasan
            self._advance(force=True)
        self.touch_count = 0

    # ---------- waktu dan telemetri ----------
    def hour(self) -> float:
        return (self.start_hour + (self.clock() - self.t0) * self.scale / 3600.0) % 24

    def _advance(self, force: bool = False) -> None:
        sim_h = (self.clock() - self.t0) * self.scale / 3600.0
        if force:
            sim_h = self._last_sim_h + 1 / 60
        dt = sim_h - self._last_sim_h
        if dt < 1 / 3600 and not force:
            return
        steps = int(min(8, max(1, math.ceil(dt / 0.25))))
        for _ in range(steps):
            self.values = self.telemetry.step((self.start_hour + sim_h) % 24, dt / steps)
        self._last_sim_h = sim_h

    # ---------- nilai per sesi ----------
    def _session_values(self, s: Session) -> dict:
        self._advance()
        v = dict(self.values)
        now = self.clock()
        if s.pinned and s.base and s.pin_time is not None:
            a = min(1.0, (now - s.pin_time) / BLEND_S)
            v["tank_level_l"] = s.base["tank_level_l"] * (1 - a) + v["tank_level_l"] * a
            v["pump_pressure_bar"] = (s.base["pump_pressure_bar"] * (1 - a)
                                      + v["pump_pressure_bar"] * a)
        if not s.pump_on and s.pump_change is not None and s.engine.depth >= 3:
            delay = PUMP_DELAY_S[0] + (zlib.crc32(s.id.encode()) % 100) / 100 * (PUMP_DELAY_S[1] - PUMP_DELAY_S[0])
            f = 1 - math.exp(-max(0.0, now - s.pump_change - delay) / PUMP_TAU_S)
            v["flow_lph"] *= (1 - f)
            v["pump_pressure_bar"] = v["pump_pressure_bar"] * (1 - f) + 0.15 * f
            v["tank_level_l"] = s.tank_hold if s.tank_hold is not None else v["tank_level_l"]
        return v

    def _input_regs(self, s: Session) -> dict[int, tuple[int, Callable[[], int]]]:
        v = self._session_values(s)
        j = lambda: int(self._rng.integers(0, 2))  # derau baca kecil
        return {
            0: (1, lambda: int(v["tank_level_l"]) + j() - 1),
            1: (1, lambda: int(v["pump_pressure_bar"] * 100) + j()),
            2: (2, lambda: int(v["flow_lph"])),
            3: (2, lambda: int(v["temp_c"] * 10) + j()),
            4: (2, lambda: 1200 + int((self.clock() - self.t0) / 3600)),
        }

    def _holding(self, s: Session) -> dict[int, tuple[int, Callable[[], int]]]:
        return {
            11: (1, lambda: 1 if s.pump_on else 0),
            0: (2, lambda: 3000), 1: (2, lambda: 19000), 2: (2, lambda: 180),
        }

    def _read(self, s: Session, table: str, addr: int, qty: int) -> list[int]:
        depth = s.engine.depth
        if table == "input":
            reg = self._input_regs(s)
        elif table == "holding":
            reg = self._holding(s)
        elif table == "coil":
            reg = {0: (2, lambda: 1 if s.pump_on else 0)}
        elif table == "discrete":
            lvl = self._session_values(s)["tank_level_l"]
            reg = {0: (2, lambda: 1 if lvl < 3000 else 0)}
        else:
            raise mp.ProtoError(mp.ILLEGAL_ADDRESS)
        out = []
        for a in range(addr, addr + qty):
            ent = reg.get(a)
            if ent is None or ent[0] > depth:
                raise mp.ProtoError(mp.ILLEGAL_ADDRESS)
            out.append(ent[1]())
        return out

    def _write(self, s: Session, req: mp.Request) -> None:
        depth = s.engine.depth
        now = self.clock()
        if req.table == "coil":
            if req.addr != 0 or depth < 2:
                raise mp.ProtoError(mp.ILLEGAL_ADDRESS)
            self._set_pump(s, bool(req.values[0]), now)
        else:
            for off, val in enumerate(req.values):
                a = req.addr + off
                if a == 11:
                    if val not in (0, 1):
                        raise mp.ProtoError(mp.ILLEGAL_VALUE)
                    self._set_pump(s, bool(val), now)
                elif a in (0, 1, 2) and depth >= 2:
                    pass
                else:
                    raise mp.ProtoError(mp.ILLEGAL_ADDRESS)
        s.writes.append((now, req.table, req.addr, list(req.values)))

    def _set_pump(self, s: Session, on: bool, now: float) -> None:
        if on == s.pump_on:
            return
        s.pump_on = on
        s.pump_change = now
        s.tank_hold = None if on else self._session_values(s)["tank_level_l"]

    # ---------- penanganan permintaan ----------
    def handle(self, src: str, unit: int, pdu: bytes, via: str = "direct"):
        """Mengembalikan (pdu_respons, tunda_detik) atau None bila diabaikan."""
        now = self.clock()
        s = self.sessions.get(src, now)
        self.touch_count += 1
        fc = pdu[0] if pdu else 0
        delay = self.profile.sample_s()
        if unit not in (1, 255):
            s.observe(now, "invalid_request", unit=unit)
            self._emit(s, via, "invalid_request", None, {"unit": unit})
            return mp.exception_pdu(fc, mp.GATEWAY_TARGET_FAIL), delay
        try:
            req = mp.parse_pdu(pdu)
        except mp.ProtoError as e:
            s.observe(now, "invalid_function" if e.code == 1 else "invalid_request",
                      unit=unit, fc=fc)
            self._emit(s, via, "invalid_function" if e.code == 1 else "invalid_request",
                       None, {"unit": unit, "fc": fc})
            return mp.exception_pdu(fc, e.code), delay

        s.observe(now, req.action, unit=unit, table=req.table, addr=req.addr,
                  qty=req.qty, fc=req.fc, is_write=req.is_write)
        if (s.read_counts[(unit, req.table, req.addr)] >= CONSISTENCY_PROBE_READS
                and not s.engine.high_tier):
            s.engine.observe_consistency_probe()          # bekukan kedalaman
        depth = s.engine.settle(s.stage) if self.adaptive else 1
        if not self.adaptive:
            s.engine.depth = 1
        target = {"unit": unit, "register": req.register}
        extra: dict = {"flags": []}
        if s.seq >= 3:
            extra["flags"].append("sequential_scan")
        if s.engine.high_tier:
            extra["flags"].append("consistency_probe")
        try:
            if req.fc in (1, 2):
                resp = mp.read_bits_response(req.fc, self._read(s, req.table, req.addr, req.qty))
            elif req.fc in (3, 4):
                resp = mp.read_regs_response(req.fc, self._read(s, req.table, req.addr, req.qty))
            elif req.fc == 43:
                resp = mp.device_id_response(self.idobj)
            else:
                self._write(s, req)
                resp = mp.write_response(req)
                extra["effect"] = "log_only"
        except mp.ProtoError as e:
            resp = mp.exception_pdu(req.fc, e.code)
            extra["exception"] = e.code
        self._emit(s, via, req.action, target, extra, depth=depth)
        return resp, delay

    def _emit(self, s: Session, via: str, action: str, target, extra: dict,
              depth: int | None = None) -> None:
        if self.bus is None:
            return
        s.events += 1
        self.bus.publish({
            "ts": time.strftime("%Y-%m-%dT%H:%M:%SZ", time.gmtime()),
            "t_mono": self.clock(),
            "satuan": self.satuan, "shadow": self.id, "proto": "modbus_tcp",
            "src": s.src, "session": s.id, "action": action, "target": target,
            "stage": s.stage, "depth": depth if depth is not None else s.engine.depth,
            "via": via, **extra,
        })

    # ---------- server TCP langsung ----------
    async def _client(self, reader, writer):
        src = writer.get_extra_info("peername")[0]
        try:
            while True:
                fr = await mp.read_frame(reader)
                if fr is None:
                    break
                tid, unit, pdu = fr
                out = self.handle(src, unit, pdu, via="direct")
                if out is None:
                    continue
                resp, delay = out
                await asyncio.sleep(delay)
                writer.write(mp.build_mbap(tid, unit, resp))
                await writer.drain()
        finally:
            writer.close()

    async def serve(self, host: str, port: int):
        return await asyncio.start_server(self._client, host, port)

