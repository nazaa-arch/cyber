"""Klien Modbus/TCP sederhana untuk penguji sesi ("penyerang simulasi").

Hanya memakai klien protokol standar dan hanya menargetkan bayangan milik
sendiri. Tidak berisi eksploit atau malware (Bab 13).
"""
from __future__ import annotations

import asyncio
import struct

from shadows import modbus_proto as mp


class ModbusClient:
    def __init__(self, host: str, port: int, unit: int = 1, timeout: float = 3.0,
                 local_addr: str | None = None):
        self.host, self.port, self.unit, self.timeout = host, port, unit, timeout
        self.local_addr = local_addr
        self.tid = 0
        self.r = self.w = None

    async def __aenter__(self):
        self.r, self.w = await asyncio.open_connection(
            self.host, self.port,
            local_addr=(self.local_addr, 0) if self.local_addr else None)
        return self

    async def __aexit__(self, *a):
        self.w.close()

    async def call(self, pdu: bytes, unit: int | None = None):
        self.tid = (self.tid + 1) & 0xFFFF
        self.w.write(mp.build_mbap(self.tid, self.unit if unit is None else unit, pdu))
        await self.w.drain()
        fr = await asyncio.wait_for(mp.read_frame(self.r), self.timeout)
        return None if fr is None else fr[2]

    async def read(self, fc: int, addr: int, qty: int = 1, unit: int | None = None):
        return await self.call(mp.build_read_request(fc, addr, qty), unit)

    async def write_reg(self, addr: int, val: int, unit: int | None = None):
        return await self.call(struct.pack(">BHH", 6, addr, val), unit)

    async def device_id(self):
        return await self.call(bytes([43, 0x0E, 0x01, 0x00]))


def values(resp: bytes | None) -> list[int] | None:
    return mp.parse_response_values(resp) if resp else None

