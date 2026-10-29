"""Skenario "penyerang simulasi" (Bab 12, 13).

Skrip internal yang HANYA menargetkan bayangan milik sendiri dan memakai
klien protokol standar. Tidak berisi eksploit atau malware.
"""
from __future__ import annotations

import asyncio
import random

from sim_attacker.modbus_client import ModbusClient


async def t1_opportunist(host: str, port: int, src: str | None = None) -> None:
    """T1: pemindai massal; baca berurutan lalu coba tulis."""
    async with ModbusClient(host, port, local_addr=src) as c:
        for a in range(0, 12):
            await c.read(4, a, 1)
        await c.write_reg(11, 0)


async def t2_targeted(host: str, port: int, src: str | None = None) -> None:
    """T2: enumerasi manual, baca level tangki, coba tulis register pompa."""
    async with ModbusClient(host, port, local_addr=src) as c:
        await c.device_id()
        await c.read(4, 0, 2)
        await c.read(3, 11, 1)
        await c.write_reg(11, 0)
        await c.read(4, 0, 2)


async def t3_consistency_tester(host: str, port: int, src: str | None = None) -> None:
    """T3: menguji konsistensi dengan membaca register yang sama berulang."""
    async with ModbusClient(host, port, local_addr=src) as c:
        for _ in range(12):
            await c.read(4, 0, 1)
            await asyncio.sleep(0.01)
        await c.write_reg(11, 1)


async def legit_operator(host: str, port: int, src: str, n: int = 20) -> None:
    """Operator sah: polling teratur ke aset asli (daftar putih)."""
    async with ModbusClient(host, port, local_addr=src) as c:
        for _ in range(n):
            await c.read(4, 0, 2)
            await asyncio.sleep(0.005)
        await c.write_reg(0, 3000)


class CuriousAttacker:
    """Penyerang penasaran (A/B bayangan statis vs adaptif).

    Terus menjelajah selama masih menemukan hal baru; pergi setelah
    `max_idle` percobaan berturut-turut tanpa informasi baru. Perilaku ini
    asumsi model, bukan klaim tentang penyerang nyata.
    """

    def __init__(self, seed: int, max_idle: int = 6):
        self.rng = random.Random(seed)
        self.max_idle = max_idle
        self.plan = ([(4, a) for a in range(0, 10)] + [(3, a) for a in range(0, 16)]
                     + [(1, 0), (2, 0)])

    def run(self, shadow, src: str, clock) -> dict:
        from shadows import modbus_proto as mp
        import struct
        known: set = set()
        idle = steps = 0
        sim_s = 0.0
        pending = [mp.build_read_request(fc, a, 1) for fc, a in self.plan]
        pending.insert(3, bytes([43, 0x0E, 0x01, 0x00]))
        pending.insert(8, struct.pack(">BHH", 6, 11, 0))
        pending.insert(12, struct.pack(">BHH", 6, 1, 18000))
        for pdu in pending:
            if idle >= self.max_idle:
                break
            think = self.rng.uniform(0.5, 2.0)
            clock.advance(think)
            sim_s += think
            resp, _ = shadow.handle(src, 1, pdu)
            steps += 1
            key = (pdu[0], pdu[1:3])
            if resp[0] & 0x80:
                idle += 1
            elif key not in known:
                known.add(key)
                idle = 0
            else:
                idle += 1
        return {"steps": steps, "dwell_sim_s": sim_s, "unique_ok": len(known)}
