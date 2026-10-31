"""Cermin Keadaan satu arah (Bab 9.4): aset asli -> bayangan, tidak pernah sebaliknya.

Hanya fungsi baca (fc 3/4) yang pernah dibentuk modul ini. Laju polling dibatasi
agar tidak membebani perangkat OT yang rapuh (Bab 14.1).
"""
from __future__ import annotations

import asyncio
import time

from shadows import modbus_proto as mp

MIN_INTERVAL_S = 0.5
_ALLOWED = (3, 4)   # data diode logis: hanya baca


class StateMirror:
    def __init__(self, real_addr: tuple[str, int], interval_s: float = 1.0, unit: int = 1,
                 mapping: tuple | None = None):
        # mapping: ((kunci, skala), ...) untuk register input 0..n-1. Dua pertama wajib dibaca;
        # sisanya dibaca best-effort (aset yang tidak punya register tsb tetap valid).
        self.mapping = mapping or (("tank_level_l", 1.0), ("pump_pressure_bar", 0.01))
        self.real_addr = real_addr
        self.interval = max(MIN_INTERVAL_S, interval_s)
        self.unit = unit
        self._snap: dict | None = None
        self._task: asyncio.Task | None = None
        self._tid = 0

    def snapshot(self) -> dict | None:
        return dict(self._snap) if self._snap else None

    async def _read(self, reader, writer, fc: int, addr: int, qty: int):
        assert fc in _ALLOWED, "cermin hanya boleh membaca"
        self._tid = (self._tid + 1) & 0xFFFF
        writer.write(mp.build_mbap(self._tid, self.unit, mp.build_read_request(fc, addr, qty)))
        await writer.drain()
        fr = await asyncio.wait_for(mp.read_frame(reader), 2.0)
        return mp.parse_response_values(fr[2]) if fr else None

    async def poll_once(self) -> dict | None:
        reader, writer = await asyncio.wait_for(asyncio.open_connection(*self.real_addr), 2.0)
        extra = None
        try:
            vals = await self._read(reader, writer, 4, 0, 2)
            if vals and len(vals) >= 2 and len(self.mapping) > 2:
                try:
                    extra = await self._read(reader, writer, 4, 2, len(self.mapping) - 2)
                except (OSError, asyncio.TimeoutError, AssertionError, ValueError):
                    extra = None
        finally:
            writer.close()
        if not vals or len(vals) < 2:
            return None
        allv = list(vals) + (list(extra) if extra and len(extra) == len(self.mapping) - 2 else [])
        snap = {k: float(v) * sc for (k, sc), v in zip(self.mapping, allv)}
        if len(self.mapping) >= 2 and self.mapping[0][1] == 1.0:
            snap[self.mapping[0][0]] = float(vals[0])
        snap["ts"] = time.monotonic()
        self._snap = snap
        return self.snapshot()

    async def _run(self):
        while True:
            try:
                await self.poll_once()
            except (OSError, asyncio.TimeoutError):
                pass
            await asyncio.sleep(self.interval)

    def start(self) -> None:
        self._task = asyncio.ensure_future(self._run())

    def stop(self) -> None:
        if self._task:
            self._task.cancel()
