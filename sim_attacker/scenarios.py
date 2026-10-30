"""Skenario "penyerang simulasi" dan sumber sah tak terdaftar (Bab 12, 13).

Skrip internal yang HANYA menargetkan bayangan milik sendiri dan memakai
klien protokol standar. Tidak berisi eksploit atau malware.
"""
from __future__ import annotations

import asyncio
import random

from sim_attacker.modbus_client import ModbusClient


async def t1_opportunist(host: str, port: int, src: str | None = None) -> None:
    """T1: pemindai massal; baca berurutan lalu coba tulis dengan nilai sentinel 0xDEAD."""
    async with ModbusClient(host, port, local_addr=src) as c:
        for a in range(0, 12):
            await c.read(4, a, 1)
        await c.write_reg(11, 0xDEAD)


async def t2_targeted(host: str, port: int, src: str | None = None) -> None:
    """T2: enumerasi manual, baca level tangki, coba tulis register pompa dengan 0xDEAD."""
    async with ModbusClient(host, port, local_addr=src) as c:
        await c.device_id()
        await c.read(4, 0, 2)
        await c.read(3, 11, 1)
        await c.write_reg(11, 0xDEAD)
        await c.read(4, 0, 2)


async def t3_consistency_tester(host: str, port: int, src: str | None = None) -> None:
    """T3: menguji konsistensi dengan membaca register yang sama berulang lalu tulis 0xDEAD."""
    async with ModbusClient(host, port, local_addr=src) as c:
        for _ in range(12):
            await c.read(4, 0, 1)
            await asyncio.sleep(0.01)
        await c.write_reg(11, 0xDEAD)


async def legit_operator(host: str, port: int, src: str, n: int = 20) -> None:
    """Operator sah: polling teratur ke aset asli (daftar putih), tulis nilai sentinel 0x1111."""
    async with ModbusClient(host, port, local_addr=src) as c:
        for _ in range(n):
            await c.read(4, 0, 2)
            await asyncio.sleep(0.005)
        await c.write_reg(0, 0x1111)


# ---------- Skenario Sumber Sah Tak Terdaftar & Kasus Uji Khusus (Poin 3) ----------

async def unlisted_technician_write(host: str, port: int, src: str) -> None:
    """Teknisi sah tapi belum terdaftar di whitelist/kebijakan: mencoba menulis register konfigurasi."""
    async with ModbusClient(host, port, local_addr=src) as c:
        await c.read(4, 0, 2)
        await c.write_reg(0, 0x2222)


async def monitoring_tool_read(host: str, port: int, src: str, n: int = 10) -> None:
    """Alat monitoring inventaris baca-saja pada laju normal (~5 Hz)."""
    async with ModbusClient(host, port, local_addr=src) as c:
        for _ in range(n):
            await c.read(4, 0, 2)
            await asyncio.sleep(0.2)


async def internal_asset_scanner(host: str, port: int, src: str) -> None:
    """Pemindai aset internal IT: membaca 20 register secara berurutan dengan laju cepat (>10 Hz)."""
    async with ModbusClient(host, port, local_addr=src) as c:
        for a in range(20):
            await c.read(4, a, 1)


async def stealth_slow_attacker(host: str, port: int, src: str) -> None:
    """Penyerang pelan baca-saja: membaca register acak tanpa pola sekuensial atau laju tinggi."""
    async with ModbusClient(host, port, local_addr=src) as c:
        for a in [0, 5, 2]:
            await c.read(4, a, 1)
            await asyncio.sleep(0.3)


# ---------- Model Penyerang A/B Dwell Time ----------

class CuriousAttacker:
    """Model 1: Penyerang penasaran (A/B bayangan statis vs adaptif).

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
        pending.insert(8, struct.pack(">BHH", 6, 11, 0xDEAD))
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


class AggressiveAttacker:
    """Model 2: Penyerang agresif (model pembanding kedua untuk uji A/B dwell time).

    Berfokus pada pemindaian cepat register kendali dan eksekusi manipulasi dini
    dengan toleransi kebuntuan (max_idle) lebih rendah dan jeda berpikir lebih pendek.
    """

    def __init__(self, seed: int, max_idle: int = 4):
        self.rng = random.Random(seed + 99)
        self.max_idle = max_idle
        self.plan = ([(4, 0), (3, 11), (4, 1), (3, 0), (4, 2), (3, 1)] +
                     [(6, 11), (6, 0), (6, 1), (6, 2)])

    def run(self, shadow, src: str, clock) -> dict:
        from shadows import modbus_proto as mp
        import struct
        known: set = set()
        idle = steps = 0
        sim_s = 0.0
        for fc, a in self.plan:
            if idle >= self.max_idle:
                break
            think = self.rng.uniform(0.2, 0.8)
            clock.advance(think)
            sim_s += think
            if fc in (3, 4):
                pdu = mp.build_read_request(fc, a, 1)
            else:
                pdu = struct.pack(">BHH", fc, a, 0xDEAD)
            resp, _ = shadow.handle(src, 1, pdu)
            steps += 1
            key = (fc, a)
            if resp[0] & 0x80:
                idle += 1
            elif key not in known:
                known.add(key)
                idle = 0
            else:
                idle += 1
        return {"steps": steps, "dwell_sim_s": sim_s, "unique_ok": len(known)}
