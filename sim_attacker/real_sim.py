"""Aset asli simulasi (hanya untuk pengujian/evaluasi): PLC Modbus sederhana.

Mencatat setiap frame yang diterima, supaya uji dapat membuktikan bahwa aset
asli tidak pernah menerima perintah dari sesi yang dialihkan.
"""
from __future__ import annotations

import asyncio

from shadows import modbus_proto as mp


class RealDeviceSim:
    def __init__(self, tank: int = 14250, pressure_x100: int = 212, latency_s: float = 0.020):
        self.input = {0: tank, 1: pressure_x100, 2: 120, 3: 285}
        self.holding = {11: 1, 0: 3000, 1: 19000, 2: 180}
        self.latency = latency_s
        self.frames: list[tuple[str, int, bytes]] = []   # (src, unit, pdu)
        self.connections = 0

    @property
    def writes(self) -> list:
        return [f for f in self.frames if f[2] and f[2][0] in mp.WRITE_FUNCS]

    def _handle(self, pdu: bytes) -> bytes:
        try:
            req = mp.parse_pdu(pdu)
        except mp.ProtoError as e:
            return mp.exception_pdu(pdu[0] if pdu else 0, e.code)
        reg = self.input if req.fc == 4 else self.holding
        if req.fc in (3, 4):
            try:
                return mp.read_regs_response(req.fc, [reg[a] for a in range(req.addr, req.addr + req.qty)])
            except KeyError:
                return mp.exception_pdu(req.fc, mp.ILLEGAL_ADDRESS)
        if req.fc == 6:
            self.holding[req.addr] = req.values[0]
            return mp.write_response(req)
        return mp.exception_pdu(req.fc, mp.ILLEGAL_FUNCTION)

    async def _client(self, reader, writer):
        src = writer.get_extra_info("peername")[0]
        self.connections += 1
        try:
            while True:
                fr = await mp.read_frame(reader)
                if fr is None:
                    break
                tid, unit, pdu = fr
                self.frames.append((src, unit, pdu))
                await asyncio.sleep(self.latency)
                writer.write(mp.build_mbap(tid, unit, self._handle(pdu)))
                await writer.drain()
        finally:
            writer.close()

    async def serve(self, host: str, port: int):
        return await asyncio.start_server(self._client, host, port)
