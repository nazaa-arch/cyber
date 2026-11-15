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
                 relay_actuator: Callable[[bool], None] | None = None,
                 flap_limit: int = 3, flap_window_s: float = 600.0,
                 clock: Callable[[], float] = time.monotonic):
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
        # Anti-flapping: bila bypass terpicu >= flap_limit kali dalam flap_window_s,
        # bypass DIKUNCI aktif dan hanya bisa dikembalikan lewat konfirmasi operator.
        # Mencegah penyerang memaksa sistem bolak-balik dengan membanjiri proxy.
        self.flap_limit = flap_limit
        self.flap_window_s = flap_window_s
        self.clock = clock
        self.engage_times: list[float] = []
        self.locked = False
        self.engaged_since: float | None = None
        self.last_reason = ""

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
            "t_mono": self.clock(), "via": "watchdog", "src": None, "session": None,
            **extra
        }
        self.history.append(rec)
        if self.bus:
            self.bus.publish(rec)

    def engage_bypass(self, reason: str = "Heartbeat timeout") -> None:
        """Mengaktifkan relai bypass fail-to-wire fisik/software."""
        if not self.is_bypass_active:
            now = self.clock()
            self.is_bypass_active = True
            self.engaged_since = now
            self.last_reason = reason
            self.engage_times = [t for t in self.engage_times if now - t < self.flap_window_s] + [now]
            self.relay_actuator(True)
            self._event("fail_to_wire_engaged", reason=reason, doktrin="Availability > Confidentiality")
            if not self.locked and len(self.engage_times) >= self.flap_limit:
                self.locked = True
                self._event("fail_to_wire_locked",
                            reason=f"Proxy gagal {len(self.engage_times)}x dalam "
                                   f"{int(self.flap_window_s)} detik; bypass dikunci sampai operator konfirmasi")

    def disengage_bypass(self, reason: str = "Proxy recovered") -> None:
        """Mengembalikan jalur normal melalui proxy Kelir saat proxy pulih."""
        if self.is_bypass_active:
            self.is_bypass_active = False
            self.engaged_since = None
            self.relay_actuator(False)
            self._event("fail_to_wire_disengaged", reason=reason)

    def confirm_restore(self, who: str = "operator") -> tuple[bool, str]:
        """Operator membuka kunci anti-flapping dan mengembalikan jalur ke Kelir.

        Ditolak bila proxy belum sehat: kembali ke Kelir yang masih mati sama saja
        memutus operator dari PLC.
        """
        if not self.is_bypass_active:
            self.locked = False
            return True, "Jalur sudah normal lewat Kelir"
        if self.healthy_beats < self.miss_threshold:
            return False, "Proxy Kelir belum sehat; bypass tetap aktif"
        self.locked = False
        self.engage_times.clear()
        self.disengage_bypass(f"Dipulihkan manual oleh {who}")
        return True, "Jalur dikembalikan ke Kelir"

    def status(self) -> dict:
        now = self.clock()
        return {"bypass_active": self.is_bypass_active, "locked": self.locked,
                "missed_beats": self.missed_beats, "healthy_beats": self.healthy_beats,
                "engaged_for_s": round(now - self.engaged_since, 1) if self.engaged_since else 0,
                "engagements_in_window": len([t for t in self.engage_times
                                              if now - t < self.flap_window_s]),
                "reason": self.last_reason if self.is_bypass_active else ""}

    def record_heartbeat(self, healthy: bool) -> bool:
        """
        Mencatat status detak jantung proxy.
        Mengembalikan True jika bypass aktif, False jika normal.
        """
        if healthy:
            self.missed_beats = 0
            self.healthy_beats += 1
            if (self.is_bypass_active and not self.locked
                    and self.healthy_beats >= self.miss_threshold):
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
