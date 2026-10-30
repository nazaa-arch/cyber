"""Modul Hardware Watchdog & Software Fail-to-Wire (Komponen D).

Doktrin OT Militer: Ketersediaan (Availability) > Kerahasiaan (Confidentiality).
Jika proxy perangkat lunak (Kelir) mengalami freeze/hang akibat badai serangan atau
OOM kernel, modul ini mendeteksi kegagalan heartbeat dan memicu relai bypass
(hardware fail-to-wire) agar jalur operator sah ke PLC fisik riil tetap terhubung langsung
tanpa jeda.
"""
from __future__ import annotations

import asyncio
import logging
import time
from typing import Callable

log = logging.getLogger("wayang.watchdog")


class WatchdogFailToWire:
    def __init__(self, satuan: str, bus=None,
                 heartbeat_interval_s: float = 1.0,
                 miss_threshold: int = 3,
                 relay_actuator: Callable[[bool], None] | None = None):
        self.satuan = satuan
        self.bus = bus
        self.interval = heartbeat_interval_s
        self.miss_threshold = miss_threshold
        self.relay_actuator = relay_actuator or self._default_relay_actuator
        self.is_bypass_active = False
        self.missed_beats = 0
        self.healthy_beats = 0
        self.running = False
        self._task: asyncio.Task | None = None
        self.history: list[dict] = []

    def _default_relay_actuator(self, bypass_state: bool) -> None:
        """Simulasi perintah ke driver relai NIC hardware (contoh: Silicom Bypass NIC / GPIO relay)."""
        action = "TERTUTUP (BYPASS LANGSUNG KE PLC)" if bypass_state else "TERBUKA (LEWAT PROXY KELIR)"
        log.warning("[WATCHDOG FAIL-TO-WIRE] Relai Mekanis: %s", action)

    def _event(self, action: str, **extra):
        rec = {
            "ts": time.strftime("%Y-%m-%dT%H:%M:%SZ", time.gmtime()),
            "satuan": self.satuan,
            "action": action,
            "bypass_active": self.is_bypass_active,
            "missed_beats": self.missed_beats,
            **extra
        }
        self.history.append(rec)
        if self.bus:
            self.bus.publish(rec)

    def engage_bypass(self, reason: str = "Heartbeat timeout") -> None:
        """Mengaktifkan relai bypass fail-to-wire fisik/software."""
        if not self.is_bypass_active:
            self.is_bypass_active = True
            self.relay_actuator(True)
            self._event("fail_to_wire_engaged", reason=reason, doktrin="Availability > Confidentiality")

    def disengage_bypass(self, reason: str = "Proxy recovered") -> None:
        """Mengembalikan jalur normal melalui proxy Kelir saat proxy pulih."""
        if self.is_bypass_active:
            self.is_bypass_active = False
            self.relay_actuator(False)
            self._event("fail_to_wire_disengaged", reason=reason)

    def record_heartbeat(self, healthy: bool) -> bool:
        """
        Mencatat status detak jantung proxy.
        Mengembalikan True jika bypass aktif, False jika normal.
        """
        if healthy:
            self.missed_beats = 0
            self.healthy_beats += 1
            if self.is_bypass_active and self.healthy_beats >= self.miss_threshold:
                self.disengage_bypass()
        else:
            self.healthy_beats = 0
            self.missed_beats += 1
            if self.missed_beats >= self.miss_threshold:
                self.engage_bypass(f"Proxy gagal merespons {self.missed_beats}x berturut-turut")
        return self.is_bypass_active

    async def monitor_loop(self, health_probe: Callable[[], bool | asyncio.Future[bool]]) -> None:
        self.running = True
        while self.running:
            try:
                if asyncio.iscoroutinefunction(health_probe):
                    healthy = await asyncio.wait_for(health_probe(), timeout=self.interval * 0.8)
                else:
                    healthy = bool(health_probe())
            except Exception:
                healthy = False

            self.record_heartbeat(healthy)
            await asyncio.sleep(self.interval)

    def start(self, health_probe: Callable) -> None:
        if self._task is None or self._task.done():
            self._task = asyncio.create_task(self.monitor_loop(health_probe))

    def stop(self) -> None:
        self.running = False
        if self._task and not self._task.done():
            self._task.cancel()
