"""Lapisan protokol Modbus/TCP minimal (Bab 6.2, 8 lapisan Protokol).

Kode kesalahan mengikuti spesifikasi (bukan "semua fungsi didukung"):
  01 fungsi tidak dikenal, 02 alamat tidak valid, 03 nilai/jumlah tidak valid,
  0B gateway target tidak merespons.
"""
from __future__ import annotations

import asyncio
import struct
from dataclasses import dataclass, field

READ_FUNCS = {1, 2, 3, 4, 43}
WRITE_FUNCS = {5, 6, 15, 16}

ILLEGAL_FUNCTION = 0x01
ILLEGAL_ADDRESS = 0x02
ILLEGAL_VALUE = 0x03
GATEWAY_TARGET_FAIL = 0x0B

ACTIONS = {
    1: "read_coils", 2: "read_discrete_inputs", 3: "read_holding_registers",
    4: "read_input_registers", 5: "write_single_coil", 6: "write_single_register",
    15: "write_multiple_coils", 16: "write_multiple_registers",
    43: "read_device_identification",
}
TABLES = {1: "coil", 2: "discrete", 3: "holding", 4: "input",
          5: "coil", 6: "holding", 15: "coil", 16: "holding", 43: "device"}
BASES = {"coil": 1, "discrete": 10001, "input": 30001, "holding": 40001, "device": 0}


class ProtoError(Exception):
    def __init__(self, code: int):
        super().__init__(f"modbus exception {code:#04x}")
        self.code = code


@dataclass
class Request:
    fc: int
    addr: int = 0
    qty: int = 1
    values: list = field(default_factory=list)
    raw: bytes = b""

    @property
    def action(self) -> str:
        return ACTIONS[self.fc]

    @property
    def table(self) -> str:
        return TABLES[self.fc]

    @property
    def is_write(self) -> bool:
        return self.fc in WRITE_FUNCS

    @property
    def register(self) -> int:
        return BASES[self.table] + self.addr


def parse_pdu(pdu: bytes) -> Request:
    if not pdu:
        raise ProtoError(ILLEGAL_VALUE)
    fc = pdu[0]
    if fc not in ACTIONS:
        raise ProtoError(ILLEGAL_FUNCTION)
    try:
        if fc in (1, 2, 3, 4):
            if len(pdu) != 5:
                raise ProtoError(ILLEGAL_VALUE)
            addr, qty = struct.unpack(">HH", pdu[1:5])
            limit = 2000 if fc in (1, 2) else 125
            if not 1 <= qty <= limit:
                raise ProtoError(ILLEGAL_VALUE)
            return Request(fc, addr, qty, raw=pdu)
        if fc in (5, 6):
            if len(pdu) != 5:
                raise ProtoError(ILLEGAL_VALUE)
            addr, val = struct.unpack(">HH", pdu[1:5])
            if fc == 5:
                if val not in (0x0000, 0xFF00):
                    raise ProtoError(ILLEGAL_VALUE)
                val = 1 if val else 0
            return Request(fc, addr, 1, [val], pdu)
        if fc in (15, 16):
            if len(pdu) < 6:
                raise ProtoError(ILLEGAL_VALUE)
            addr, qty, bc = struct.unpack(">HHB", pdu[1:6])
            data = pdu[6:]
            if len(data) != bc:
                raise ProtoError(ILLEGAL_VALUE)
            if fc == 16:
                if not 1 <= qty <= 123 or bc != qty * 2:
                    raise ProtoError(ILLEGAL_VALUE)
                vals = list(struct.unpack(">" + "H" * qty, data))
            else:
                if not 1 <= qty <= 1968 or bc != (qty + 7) // 8:
                    raise ProtoError(ILLEGAL_VALUE)
                vals = [(data[i // 8] >> (i % 8)) & 1 for i in range(qty)]
            return Request(fc, addr, qty, vals, pdu)
        if fc == 43:
            if len(pdu) != 4 or pdu[1] != 0x0E:
                raise ProtoError(ILLEGAL_VALUE)
            return Request(fc, pdu[3], 1, [pdu[2]], pdu)
    except struct.error:
        raise ProtoError(ILLEGAL_VALUE)
    raise ProtoError(ILLEGAL_FUNCTION)


def exception_pdu(fc: int, code: int) -> bytes:
    return bytes([(fc | 0x80) & 0xFF, code])


def read_regs_response(fc: int, values: list[int]) -> bytes:
    return bytes([fc, len(values) * 2]) + struct.pack(">" + "H" * len(values),
                                                      *[v & 0xFFFF for v in values])


def read_bits_response(fc: int, bits: list[int]) -> bytes:
    out = bytearray((len(bits) + 7) // 8)
    for i, b in enumerate(bits):
        if b:
            out[i // 8] |= 1 << (i % 8)
    return bytes([fc, len(out)]) + bytes(out)


def write_response(req: Request) -> bytes:
    if req.fc in (5, 6):
        return req.raw
    return struct.pack(">BHH", req.fc, req.addr, req.qty)


def device_id_response(objects: dict[int, str]) -> bytes:
    body = b"".join(bytes([oid, len(v)]) + v.encode() for oid, v in sorted(objects.items()))
    return bytes([43, 0x0E, 0x01, 0x01, 0x00, 0x00, len(objects)]) + body


def build_mbap(tid: int, unit: int, pdu: bytes) -> bytes:
    return struct.pack(">HHHB", tid, 0, len(pdu) + 1, unit) + pdu


def build_read_request(fc: int, addr: int, qty: int) -> bytes:
    return struct.pack(">BHH", fc, addr, qty)


async def read_frame(reader: asyncio.StreamReader):
    """Baca satu frame MBAP. Mengembalikan (tid, unit, pdu) atau None bila koneksi tutup."""
    try:
        head = await reader.readexactly(7)
    except (asyncio.IncompleteReadError, ConnectionError):
        return None
    tid, pid, length, unit = struct.unpack(">HHHB", head)
    if pid != 0 or not 2 <= length <= 260:
        return None
    try:
        pdu = await reader.readexactly(length - 1)
    except (asyncio.IncompleteReadError, ConnectionError):
        return None
    return tid, unit, pdu


def parse_response_values(pdu: bytes) -> list[int] | None:
    """Ambil nilai register dari respons fc 3/4 (dipakai Cermin Keadaan)."""
    if len(pdu) < 2 or pdu[0] & 0x80 or pdu[0] not in (3, 4):
        return None
    n = pdu[1] // 2
    return list(struct.unpack(">" + "H" * n, pdu[2:2 + n * 2]))
