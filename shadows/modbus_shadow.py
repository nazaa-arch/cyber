"""Bayangan Modbus: meniru PLC/RTU dengan telemetri hidup (Bab 6.2, 8, 9.2, 9.4).

Semua perintah tulis berakhir log-only (Bab 9.2): tidak ada jalur tulis ke
aset asli dari modul ini.
"""
from __future__ import annotations

import asyncio
import math
import time
import zlib
from collections import deque
from typing import Callable

import numpy as np

from engine.gamelan import Gamelan
from kelir.session import Session, SessionRegistry
from shadows import modbus_proto as mp
from shadows import profiles
from telemetry.models import DepoBBMTelemetry

BLEND_S = 60.0            # lama "berpisah" dari nilai cermin ke jalur fiktif
PUMP_DELAY_S = (1.5, 3.0)  # jeda realistis efek perintah palsu
PUMP_TAU_S = 6.0
CONSISTENCY_PROBE_READS = 8


class LatencyProfile:
    """Profil latensi bayangan adaptif yang mempelajari distribusi aset riil.

    Meniru sebaran latensi aset asli secara dinamis (exponential moving average),
    sehingga selisih waktu respons (delta latency) sebelum vs sesudah pengalihan
    mendekati 0 untuk mencegah deteksi oleh penyerang cerdas.
    """

    def __init__(self, seed: int, base_ms: float = 20.0, sigma: float = 0.2,
                 plc_scan_ms: float = 20.0):
        self.rng = np.random.default_rng(seed + 11)
        self.base_ms = base_ms
        self.sigma = sigma
        self.plc_scan_ms = plc_scan_ms
        self.history: deque[float] = deque(maxlen=100)
        self.history.append(base_ms)
        self.learned_mean: float = base_ms
        self.learned_std: float = 2.0

    def match(self, real_ms: float) -> None:
        """Mempelajari distribusi latensi aset asli saat beroperasi (Bab 9.4)."""
        clamped = max(1.0, min(real_ms, 200.0))
        self.history.append(clamped)
        self.learned_mean = 0.85 * self.learned_mean + 0.15 * clamped
        if len(self.history) >= 5:
            self.learned_std = max(0.5, float(np.std(list(self.history))))
        self.base_ms = self.learned_mean

    def sample_s(self) -> float:
        """Menghasilkan tunda respons yang persis mengikuti profil aset asli."""
        std = max(0.5, min(self.learned_std, 4.0))
        sampled_ms = float(self.rng.normal(self.learned_mean, std))
        sampled_ms = max(1.0, min(sampled_ms, 250.0))
        return sampled_ms / 1000.0


class ShadowDevice:
    def __init__(self, shadow_id: str, satuan: str, seed: int,
                 sessions: SessionRegistry, bus: Gamelan | None = None,
                 clock: Callable[[], float] = time.monotonic,
                 time_scale: float = 1.0, start_hour: float | None = None,
                 capacity_l: float = 20000.0, vendor: str = "Generik",
                 adaptive: bool = True, kind: str = "bbm"):
        self.kind = kind              # bbm | genset | cctv | gateway
        self.spec = profiles.SPECS.get(kind)
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
        self.idobj = {
            0: vendor if vendor != "Generik" else "Schneider Electric",
            1: f"TM221CE24T-{100 + seed % 50}",
            2: "V2.1.4",
        }
        # Graceful Degradation Ladder (Tangga Penurunan Beban):
        # 0: Full Dynamic Physics (Simulasi diferensial fluida & tangga lengkap)
        # 1: Cached Snapshot (Bekukan persamaan diferensial, layani snapshot berkala; hemat 80% CPU)
        # 2: Syntactic Fast (Respons statis minimal tanpa kalkulasi fisika saat beban ekstrem)
        self.degradation_tier: int = 0
        if self.spec:
            self.telemetry = self.spec.telemetry_cls(seed)
            self.values = dict(self.spec.initial)
            self.idobj = {0: self.spec.vendor, 1: f"{self.spec.model}-{100 + seed % 50}",
                          2: self.spec.firmware}
        self._cache_v: dict = {}
        self._cache_t: float = 0.0
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
        now = self.clock()
        # Tangga Tingkat 1 & 2: Gunakan cache snapshot jika degradation tier aktif
        if self.degradation_tier >= 1 and self._cache_v and (now - self._cache_t) < 2.5:
            return dict(self._cache_v)

        self._advance()
        v = dict(self.values)
        if self.spec:
            v = self.spec.session_values(v, s, now, BLEND_S)
            if self.degradation_tier >= 1:
                self._cache_v = dict(v)
                self._cache_t = now
            return v
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

        if self.degradation_tier >= 1:
            self._cache_v = dict(v)
            self._cache_t = now
        return v

    def _input_regs(self, s: Session) -> dict[int, tuple[int, Callable[[], int]]]:
        v = self._session_values(s)
        j = lambda: int(self._rng.integers(0, 2))  # derau baca kecil
        if self.spec:
            return self.spec.input_regs(v, s, j, self.clock(), self.t0)
        return {
            # Blok 1: Sistem & Tangki Utama (Alamat 0 - 49)
            0: (1, lambda: int(v["tank_level_l"]) + j() - 1),
            1: (1, lambda: int(v["pump_pressure_bar"] * 100) + j()),
            2: (2, lambda: int(v["flow_lph"])),
            3: (2, lambda: int(v["temp_c"] * 10) + j()),
            4: (2, lambda: 1200 + int((self.clock() - self.t0) / 3600)),
            5: (2, lambda: 285 + j()),                              # Temp ruang pompa 28.5 C
            6: (2, lambda: 1013 + j()),                             # Tekanan uap tangki 101.3 kPa
            7: (2, lambda: 15),                                     # Kadar air dasar tangki 15 mm
            8: (2, lambda: 8400 + j()),                             # Densitas solar 840.0 kg/m3
            10: (2, lambda: 0x0007 if s.pump_on else 0x0001),       # Status kata sistem (bitfield)
            # GAP 1 (Alamat 50 - 99): Celah tak teralokasi -> Exception 02

            # Blok 2: Pompa Transfer & Distribusi (Alamat 100 - 125)
            100: (2, lambda: 1 if s.pump_on else 0),                 # Status Operasi Pompa 1 (Run/Stop)
            101: (2, lambda: 1450 if s.pump_on else 0),              # RPM Pompa 1
            102: (2, lambda: 245 if s.pump_on else 0),               # Arus Pompa 1 (24.5 A)
            103: (2, lambda: 520 if s.pump_on else 280),             # Temp Motor Pompa 1 (52.0 C)
            104: (2, lambda: 18 if s.pump_on else 0),                # Getaran Pompa 1 (1.8 mm/s)
            110: (2, lambda: 0),                                     # Status Pompa 2 (Standby)
            111: (2, lambda: 0),                                     # RPM Pompa 2
            112: (2, lambda: 0),                                     # Arus Pompa 2
            113: (2, lambda: 280),                                   # Temp Pompa 2
            120: (2, lambda: 12),                                    # Totalizer High Word
            121: (2, lambda: 34500),                                 # Totalizer Low Word
            # GAP 2 (Alamat 126 - 199): Celah tak teralokasi -> Exception 02

            # Blok 3: Tangki Cadangan / Buffer Reserve (Alamat 200 - 225)
            200: (2, lambda: 8500),                                  # Level Tangki Cadangan (8.500 L)
            201: (2, lambda: 140),                                   # Tekanan Tangki Cadangan (1.40 bar)
            202: (2, lambda: 1),                                     # Katup Buffer (1=Open)
            203: (2, lambda: 8),                                     # Kadar air cadangan 8 mm
            210: (2, lambda: 1),                                     # Status ESD Valve (1=Normal)
            # GAP 3 (Alamat 226 - 299): Celah tak teralokasi -> Exception 02

            # Blok 4: Genset & ATS Power Backup (Alamat 300 - 330)
            300: (2, lambda: 1),                                     # Status Grid PLN (1=Normal)
            301: (2, lambda: 0),                                     # Status Genset (0=Standby)
            302: (2, lambda: 398),                                   # Tegangan Bus (398 V)
            303: (2, lambda: 500),                                   # Frekuensi Grid (50.0 Hz)
            304: (2, lambda: 268),                                   # Tegangan Aki Starter (26.8 V)
            305: (2, lambda: 92),                                    # Level Tangki Solar Genset (92%)
            310: (2, lambda: 45),                                    # Daya Aktif Beban (45 kW)
            # GAP 4 (Alamat 331 - 999+): Celah tak teralokasi -> Exception 02
        }

    def _holding(self, s: Session) -> dict[int, tuple[int, Callable[[], int]]]:
        if self.spec:
            return self.spec.holding(s)
        return {
            # Blok 1: Parameter Kendali & Setpoint (0 - 49)
            0: (2, lambda: 3000),                                    # Setpoint Min Tangki (3000 L)
            1: (2, lambda: 19000),                                   # Setpoint Max Tangki (19000 L)
            2: (2, lambda: 180),                                     # Setpoint Overpressure (1.80 bar)
            10: (2, lambda: 3),                                      # Mode Operasi (3=Auto)
            11: (1, lambda: 1 if s.pump_on else 0),                  # Kendali Pompa Utama (1=ON, 0=OFF)
            20: (2, lambda: 5000),                                   # Setpoint Alir Target (5000 lph)
            21: (2, lambda: 60),                                     # Watchdog Timeout SCADA (60 dtk)
            # GAP 1 (50 - 99): Exception 02

            # Blok 2: Pengaturan Pompa Transfer (100 - 125)
            100: (2, lambda: 1 if s.pump_on else 0),                 # Kendali Pompa 1 (1/0)
            105: (2, lambda: 350),                                   # Batas Arus Max Pompa 1 (35.0 A)
            110: (2, lambda: 0),                                     # Kendali Pompa 2 (1/0)
            115: (2, lambda: 350),                                   # Batas Arus Max Pompa 2
            # GAP 2 (126 - 199): Exception 02

            # Blok 3: Pengaturan Tangki Cadangan (200 - 225)
            200: (2, lambda: 2000),                                  # Setpoint Min Cadangan (2000 L)
            202: (2, lambda: 1),                                     # Kendali Katup Buffer (1=Open)
            210: (2, lambda: 1),                                     # Reset Interlock ESD
            # GAP 3 (226 - 299): Exception 02

            # Blok 4: Pengaturan ATS & Genset (300 - 330)
            300: (2, lambda: 1),                                     # Mode ATS (1=Auto Transfer)
            301: (2, lambda: 0),                                     # Remote Start Genset
            305: (2, lambda: 340),                                   # Ambang Undervoltage PLN (340 V)
            # GAP 4 (331 - 999+): Exception 02
        }

    def _read(self, s: Session, table: str, addr: int, qty: int) -> list[int]:
        depth = s.engine.depth
        if table == "input":
            reg = self._input_regs(s)
        elif table == "holding":
            reg = self._holding(s)
        elif table == "coil" and self.spec:
            reg = self.spec.coils(s)
        elif table == "discrete" and self.spec:
            reg = self.spec.discrete(self._session_values(s), s)
        elif table == "coil":
            reg = {
                0: (1, lambda: 1 if s.pump_on else 0),
                100: (2, lambda: 1 if s.pump_on else 0),
                110: (2, lambda: 0),
                202: (2, lambda: 1),
                210: (2, lambda: 1),
                301: (2, lambda: 0),
            }
        elif table == "discrete":
            lvl = self._session_values(s)["tank_level_l"]
            reg = {
                0: (1, lambda: 1 if lvl < 3000 else 0),
                1: (2, lambda: 1 if lvl > 19000 else 0),
                10: (2, lambda: 1 if s.pump_on else 0),
                202: (2, lambda: 1),
            }
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
        if self.spec:
            act = self.spec.actuator_addr
            if req.table == "coil":
                for off, val in enumerate(req.values):
                    addr = req.addr + off
                    if addr not in self.spec.valid_coils or (addr != act and depth < 2):
                        raise mp.ProtoError(mp.ILLEGAL_ADDRESS)
                    if addr == act:
                        self._set_pump(s, bool(val), now)
            else:
                for off, val in enumerate(req.values):
                    a = req.addr + off
                    if a not in self.spec.valid_holding:
                        raise mp.ProtoError(mp.ILLEGAL_ADDRESS)
                    if a == act:
                        if val not in (0, 1):
                            raise mp.ProtoError(mp.ILLEGAL_VALUE)
                        self._set_pump(s, bool(val), now)
            s.writes.append((now, req.table, req.addr, list(req.values)))
            return
        if req.table == "coil":
            valid_coils = {0, 100, 110, 202, 210, 301}
            for off, val in enumerate(req.values):
                addr = req.addr + off
                if addr not in valid_coils or (addr != 0 and depth < 2):
                    raise mp.ProtoError(mp.ILLEGAL_ADDRESS)
                if addr in (0, 100):
                    self._set_pump(s, bool(val), now)
        else:
            valid_holding = {
                0, 1, 2, 10, 11, 20, 21,
                100, 105, 110, 115,
                200, 202, 210,
                300, 301, 305
            }
            for off, val in enumerate(req.values):
                a = req.addr + off
                if a not in valid_holding:
                    raise mp.ProtoError(mp.ILLEGAL_ADDRESS)
                if a in (11, 100):
                    if val not in (0, 1):
                        raise mp.ProtoError(mp.ILLEGAL_VALUE)
                    self._set_pump(s, bool(val), now)
                elif a in valid_holding and depth >= 2:
                    pass
                elif a in (0, 1, 2, 11):
                    pass
                else:
                    raise mp.ProtoError(mp.ILLEGAL_ADDRESS)
        s.writes.append((now, req.table, req.addr, list(req.values)))

    def _set_pump(self, s: Session, on: bool, now: float) -> None:
        if on == s.pump_on:
            return
        s.pump_on = on
        s.pump_change = now
        if self.spec:
            s.tank_hold = None
            return
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

