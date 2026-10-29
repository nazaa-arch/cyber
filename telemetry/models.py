"""Mesin Telemetri: model fisik ringan (Bab 8, "Model telemetri").

L(t+D) = L(t) - q(t)*D + r(t)*D + eps_L
T(t)   = T0 + A*sin(2*pi*(t-phi)/24h) + eps_T
P(t)   = P0 + k*q(t) + eps_P

Semua derau (eps) memakai benih (seed) per satuan agar tidak ada dua
bayangan dengan sidik jari identik (Bab 7).
"""
from __future__ import annotations

import math

import numpy as np

# Profil pemakaian harian (liter/jam, per kapasitas 20.000 L), indeks = jam 0..23.
_DRAW_HARIAN = [20, 15, 10, 10, 15, 40, 90, 140, 160, 150, 130, 120,
                110, 120, 130, 140, 150, 130, 100, 70, 50, 40, 30, 25]


class TankModel:
    def __init__(self, capacity_l: float = 20000.0, seed: int = 0,
                 refill_hour: float = 22.0, refill_lph: float = 1500.0,
                 refill_threshold: float = 0.35):
        self.rng = np.random.default_rng(seed)
        self.capacity = capacity_l
        self.level = capacity_l * float(self.rng.uniform(0.6, 0.85))
        self.scale = capacity_l / 20000.0 * float(self.rng.uniform(0.9, 1.1))
        self.refill_hour = refill_hour + float(self.rng.uniform(-1.0, 1.0))
        self.refill_lph = refill_lph
        self.refill_threshold = refill_threshold
        self.flow = 0.0  # q(t), liter/jam

    def draw_rate(self, hour: float) -> float:
        h = int(hour) % 24
        nxt = _DRAW_HARIAN[(h + 1) % 24]
        frac = hour - int(hour)
        base = _DRAW_HARIAN[h] * (1 - frac) + nxt * frac
        return base * self.scale

    def step(self, hour: float, dt_h: float) -> float:
        q = max(0.0, self.draw_rate(hour) + float(self.rng.normal(0, 3.0)))
        refilling = (abs(((hour - self.refill_hour + 12) % 24) - 12) < 1.5
                     and self.level < self.refill_threshold * self.capacity * 1.6)
        r = self.refill_lph if refilling else 0.0
        eps = float(self.rng.normal(0, 5.0))
        self.level = min(self.capacity, max(0.0, self.level - q * dt_h + r * dt_h + eps))
        self.flow = q
        return self.level


class TemperatureModel:
    def __init__(self, seed: int = 0, t0: float = 27.0, amplitude: float = 4.0):
        self.rng = np.random.default_rng(seed + 1)
        self.t0 = t0 + float(self.rng.uniform(-1.5, 1.5))
        self.a = amplitude * float(self.rng.uniform(0.8, 1.2))
        self.phi = 9.0 + float(self.rng.uniform(-1.0, 1.0))  # puncak sore hari

    def value(self, hour: float) -> float:
        eps = float(self.rng.normal(0, 0.15))
        return self.t0 + self.a * math.sin(2 * math.pi * (hour - self.phi) / 24.0) + eps


class PumpPressureModel:
    """Tekanan pompa berkorelasi dengan aliran: P = P0 + k*q + eps."""

    def __init__(self, seed: int = 0, p0: float = 1.8, k: float = 0.004,
                 noise: float = 0.02):
        self.rng = np.random.default_rng(seed + 2)
        self.p0 = p0 + float(self.rng.uniform(-0.1, 0.1))
        self.k = k * float(self.rng.uniform(0.9, 1.1))
        self.noise = noise

    def value(self, flow_lph: float) -> float:
        return self.p0 + self.k * flow_lph + float(self.rng.normal(0, self.noise))


class DepoBBMTelemetry:
    """Satu Lakon Depo BBM: tangki, pompa, suhu bergerak konsisten."""

    def __init__(self, seed: int, capacity_l: float = 20000.0, noise: float = 0.02):
        self.tank = TankModel(capacity_l, seed)
        self.temp = TemperatureModel(seed)
        self.pump = PumpPressureModel(seed, noise=noise)

    def step(self, hour: float, dt_h: float = 1 / 60) -> dict:
        level = self.tank.step(hour, dt_h)
        return {
            "tank_level_l": level,
            "pump_pressure_bar": self.pump.value(self.tank.flow),
            "flow_lph": self.tank.flow,
            "temp_c": self.temp.value(hour),
        }
