"""Profil aset bayangan selain Depo BBM: Genset/ATS, Gerbang-CCTV, Gateway C4ISR.

Setiap profil memiliki model telemetri sendiri, peta register Modbus sendiri
(selaras dengan `lakon/*.yaml`), dan efek perintah-palsu sendiri. Seluruh perintah
tulis tetap *log-only* (tidak ada jalur tulis ke aset asli).

Konvensi aktuator utama (`Session.pump_on`):  1 = aman/berjalan, 0 = dimanipulasi.
  * genset  : 1 = genset on-load,        0 = trip (daya jatuh ke 0)
  * cctv    : 1 = palang terkunci,       0 = palang dibuka (sudut -> 90 derajat)
  * gateway : 1 = uplink aktif,          0 = uplink diputus (throughput jatuh)
"""
from __future__ import annotations

import math
import zlib
from dataclasses import dataclass, field
from typing import Callable

import numpy as np

RegMap = dict  # addr -> (min_depth, callable)

EFFECT_DELAY_S = (1.5, 3.0)
EFFECT_TAU_S = 4.0


# ------------------------------------------------------------------ telemetri
class GensetTelemetry:
    """Beban genset mengikuti jam kerja; frekuensi ~50 Hz; suhu mesin korelatif beban."""

    def __init__(self, seed: int, capacity_l: float = 0.0):
        self.rng = np.random.default_rng(seed + 501)
        self.fuel = 92.0

    def step(self, hour: float, dt_h: float = 1 / 60) -> dict:
        day = max(0.0, math.sin((hour - 6.0) / 12.0 * math.pi))
        power = 36.0 + 16.0 * day + float(self.rng.normal(0, 0.5))
        self.fuel = max(15.0, self.fuel - 0.02 * dt_h * 60)
        return {
            "power_load_kw": power,
            "frequency_hz": 50.02 + float(self.rng.normal(0, 0.03)),
            "engine_temp_c": 62.0 + 0.33 * power + float(self.rng.normal(0, 0.2)),
            "voltage_v": 380.0 + float(self.rng.normal(0, 1.2)),
            "fuel_pct": self.fuel,
        }


class GateTelemetry:
    """Gerbang pangkalan: palang terkunci, kamera online, kendaraan harian bertambah."""

    def __init__(self, seed: int, capacity_l: float = 0.0):
        self.rng = np.random.default_rng(seed + 601)
        self.vehicles = 14.0

    def step(self, hour: float, dt_h: float = 1 / 60) -> dict:
        if 6.0 <= hour <= 18.0:
            self.vehicles += 0.04 * dt_h * 60
        return {
            "gate_angle_deg": 0.0,
            "cams_online": 4.0,
            "beam_ok": 1.0,
            "vehicles_today": float(int(self.vehicles)),
        }


class GatewayTelemetry:
    """Gateway C4ISR: throughput, tautan aktif, CPU."""

    def __init__(self, seed: int, capacity_l: float = 0.0):
        self.rng = np.random.default_rng(seed + 701)

    def step(self, hour: float, dt_h: float = 1 / 60) -> dict:
        return {
            "throughput_mbps": 1250.0 + float(self.rng.normal(0, 18.0)),
            "active_links": 5.0,
            "cpu_pct": 24.0 + 6.0 * math.sin(hour / 24 * 2 * math.pi) + float(self.rng.normal(0, 0.8)),
            "ledger_height": 0.0,
        }


# ------------------------------------------------------------------ efek palsu
def _ramp(s, now: float) -> float | None:
    """Faktor 0..1 efek perintah-palsu sejak aktuator dimanipulasi (None bila belum aktif)."""
    if s.pump_on or s.pump_change is None or s.engine.depth < 3:
        return None
    lo, hi = EFFECT_DELAY_S
    delay = lo + (zlib.crc32(s.id.encode()) % 100) / 100 * (hi - lo)
    return 1 - math.exp(-max(0.0, now - s.pump_change - delay) / EFFECT_TAU_S)


def _blend(v: dict, s, now: float, blend_s: float, keys: tuple[str, ...]) -> dict:
    if s.pinned and s.base and s.pin_time is not None:
        a = min(1.0, (now - s.pin_time) / blend_s)
        for k in keys:
            if k in s.base:
                v[k] = s.base[k] * (1 - a) + v[k] * a
    return v


def _genset_session(v, s, now, blend_s):
    v = _blend(v, s, now, blend_s, ("power_load_kw", "frequency_hz"))
    f = _ramp(s, now)
    if f is not None:
        v["power_load_kw"] *= (1 - f)
        v["frequency_hz"] *= (1 - f)
        v["voltage_v"] *= (1 - f)
    return v


def _gate_session(v, s, now, blend_s):
    v = _blend(v, s, now, blend_s, ("gate_angle_deg", "cams_online"))
    f = _ramp(s, now)
    if f is not None:
        v["gate_angle_deg"] = 90.0 * f
        v["beam_ok"] = 0.0 if f > 0.5 else 1.0
    return v


def _gateway_session(v, s, now, blend_s):
    v = _blend(v, s, now, blend_s, ("throughput_mbps", "active_links"))
    f = _ramp(s, now)
    if f is not None:
        v["throughput_mbps"] = v["throughput_mbps"] * (1 - f) + 80.0 * f
        v["active_links"] = max(0.0, v["active_links"] * (1 - f))
    return v


# ------------------------------------------------------------------ peta register
def _genset_input(v, s, j, now, t0):
    return {
        0: (1, lambda: int(v["power_load_kw"] * 10) + j()),
        1: (1, lambda: int(v["frequency_hz"] * 100) + j()),
        2: (2, lambda: int(v["engine_temp_c"] * 10) + j()),
        3: (2, lambda: int(v["voltage_v"] * 10) + j()),
        10: (1, lambda: int(v["power_load_kw"])),
        11: (1, lambda: int(v["frequency_hz"] * 100)),
        12: (2, lambda: int(v["engine_temp_c"])),
        20: (2, lambda: int(v["fuel_pct"])),
        21: (2, lambda: 1 if s.pump_on else 0),            # 1 = on-load, 0 = trip
        22: (3, lambda: 1200 + int((now - t0) / 3600)),    # jam operasi
    }


def _genset_holding(s):
    return {20: (1, lambda: 1 if s.pump_on else 0), 21: (2, lambda: 1), 22: (2, lambda: 5)}


def _gate_input(v, s, j, now, t0):
    return {
        0: (1, lambda: int(v["gate_angle_deg"])),
        1: (1, lambda: int(v["cams_online"])),
        2: (1, lambda: int(v["beam_ok"])),
        3: (2, lambda: int(v["vehicles_today"])),
        10: (2, lambda: 1 if s.pump_on else 0),            # 1 = terkunci
        11: (3, lambda: 1080),                             # resolusi aliran utama
    }


def _gate_holding(s):
    return {30: (1, lambda: 1 if s.pump_on else 0), 31: (2, lambda: 15)}


def _gateway_input(v, s, j, now, t0):
    return {
        0: (1, lambda: int(v["throughput_mbps"])),
        1: (1, lambda: int(v["active_links"])),
        2: (2, lambda: int(v["cpu_pct"] * 10)),
        3: (2, lambda: 1482 + int((now - t0) / 60)),
        10: (2, lambda: 1 if s.pump_on else 0),
    }


def _gateway_holding(s):
    return {40: (1, lambda: 1 if s.pump_on else 0), 41: (2, lambda: 2)}


@dataclass
class ProfileSpec:
    kind: str
    telemetry_cls: type
    initial: dict
    vendor: str
    model: str
    firmware: str
    mirror_keys: tuple          # ((kunci, skala), ...) untuk register input 0..n-1 (wajib: 2 pertama)
    session_values: Callable
    input_regs: Callable
    holding: Callable
    actuator_addr: int          # alamat holding/coil aktuator utama
    valid_holding: set = field(default_factory=set)
    valid_coils: set = field(default_factory=set)
    gate_keys: tuple = ()

    def coils(self, s) -> RegMap:
        return {self.actuator_addr: (1, lambda: 1 if s.pump_on else 0)}

    def discrete(self, v, s) -> RegMap:
        if self.kind == "genset":
            return {0: (1, lambda: 1 if v["power_load_kw"] > 70 else 0),
                    1: (2, lambda: 0 if s.pump_on else 1)}
        if self.kind == "cctv":
            return {0: (1, lambda: 0 if v["beam_ok"] >= 1 else 1),
                    1: (1, lambda: 1 if v["gate_angle_deg"] > 5 else 0)}
        return {0: (1, lambda: 0), 1: (2, lambda: 0 if s.pump_on else 1)}


SPECS: dict[str, ProfileSpec] = {
    "genset": ProfileSpec(
        "genset", GensetTelemetry,
        {"power_load_kw": 46.8, "frequency_hz": 50.02, "engine_temp_c": 78.0,
         "voltage_v": 382.0, "fuel_pct": 92.0},
        "DeepSea Electronics", "DSE7320MKII", "V4.2.1",
        (("power_load_kw", 0.1), ("frequency_hz", 0.01), ("engine_temp_c", 0.1), ("voltage_v", 0.1)),
        _genset_session, _genset_input, _genset_holding, 20,
        valid_holding={20, 21, 22}, valid_coils={20}),
    "cctv": ProfileSpec(
        "cctv", GateTelemetry,
        {"gate_angle_deg": 0.0, "cams_online": 4.0, "beam_ok": 1.0, "vehicles_today": 14.0},
        "Hikvision", "DS-K3B601", "V3.4.2",
        (("gate_angle_deg", 1.0), ("cams_online", 1.0), ("beam_ok", 1.0), ("vehicles_today", 1.0)),
        _gate_session, _gate_input, _gate_holding, 30,
        valid_holding={30, 31}, valid_coils={30}),
    "gateway": ProfileSpec(
        "gateway", GatewayTelemetry,
        {"throughput_mbps": 1250.0, "active_links": 5.0, "cpu_pct": 24.0, "ledger_height": 0.0},
        "Pusinfolahta", "DALANG-GW", "V1.0.0",
        (("throughput_mbps", 1.0), ("active_links", 1.0), ("cpu_pct", 0.1), ("ledger_height", 1.0)),
        _gateway_session, _gateway_input, _gateway_holding, 40,
        valid_holding={40, 41}, valid_coils={40}),
}

# Nilai awal register input 0..3 pada simulator aset asli (RealDeviceSim) per jenis.
REAL_INPUT = {
    "bbm": ({0: 14250, 1: 212, 2: 120, 3: 285}, {11: 1, 0: 3000, 1: 19000, 2: 180}),
    "genset": ({0: 468, 1: 5002, 2: 785, 3: 3824}, {20: 1, 21: 1, 22: 5}),
    "cctv": ({0: 0, 1: 4, 2: 1, 3: 14}, {30: 1, 31: 15}),
    "gateway": ({0: 1250, 1: 5, 2: 240, 3: 1482}, {40: 1, 41: 2}),
}

# Pemetaan cermin (kunci, skala) per jenis; BBM = perilaku asli.
MIRROR_MAP = {
    "bbm": (("tank_level_l", 1.0), ("pump_pressure_bar", 0.01), ("flow_lph", 1.0), ("temp_c", 0.1)),
    **{k: sp.mirror_keys for k, sp in SPECS.items()},
}
