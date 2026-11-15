"""Buat pcap sintetis skenario lab: penyerang membaca lalu MENULIS register PLC.

Tidak ada paket yang dikirim ke jaringan; berkas ini hanya rekaman buatan untuk
diputar Suricata (`suricata -r`). Isi:

* 10.10.5.30 (HMI sah, MODBUS_OPERATORS) membaca holding register   -> tidak ada alert
* 10.10.5.90 (penyerang) membaca, lalu fc 6 Write Single Register    -> alert sid 9799001

Pakai: python integrations/lab/make_pcap.py integrations/lab/pcap/serangan-modbus.pcap
"""
from __future__ import annotations

import pathlib
import struct
import sys

PLC = "10.10.5.20"
HMI = "10.10.5.30"
ATTACKER = "10.10.5.90"


def _ip(a: str) -> bytes:
    return bytes(int(x) for x in a.split("."))


def _csum(data: bytes) -> int:
    if len(data) % 2:
        data += b"\0"
    s = sum(struct.unpack(f"!{len(data) // 2}H", data))
    while s >> 16:
        s = (s & 0xFFFF) + (s >> 16)
    return ~s & 0xFFFF


def _packet(src, dst, sport, dport, seq, ack, flags, payload=b""):
    tcp_hdr = struct.pack("!HHIIBBHHH", sport, dport, seq, ack, 5 << 4, flags, 65535, 0, 0)
    pseudo = _ip(src) + _ip(dst) + struct.pack("!BBH", 0, 6, len(tcp_hdr) + len(payload))
    c = _csum(pseudo + tcp_hdr + payload)
    tcp_hdr = tcp_hdr[:16] + struct.pack("!H", c) + tcp_hdr[18:]
    total = 20 + len(tcp_hdr) + len(payload)
    ip_hdr = struct.pack("!BBHHHBBH4s4s", 0x45, 0, total, 1, 0x4000, 64, 6, 0, _ip(src), _ip(dst))
    ip_hdr = ip_hdr[:10] + struct.pack("!H", _csum(ip_hdr)) + ip_hdr[12:]
    eth = b"\x02\x00\x00\x00\x00\x02" + b"\x02\x00\x00\x00\x00\x01" + b"\x08\x00"
    return eth + ip_hdr + tcp_hdr + payload


def _mbap(tid: int, pdu: bytes, unit: int = 1) -> bytes:
    return struct.pack("!HHHB", tid, 0, len(pdu) + 1, unit) + pdu


class Flow:
    SYN, ACK, PSH, FIN = 0x02, 0x10, 0x08, 0x01

    def __init__(self, cli, srv, sport, out):
        self.cli, self.srv, self.sport, self.out = cli, srv, sport, out
        self.cseq, self.sseq = 1000, 5000

    def _emit(self, *a):
        self.out.append(_packet(*a))

    def open(self):
        self._emit(self.cli, self.srv, self.sport, 502, self.cseq, 0, self.SYN)
        self._emit(self.srv, self.cli, 502, self.sport, self.sseq, self.cseq + 1, self.SYN | self.ACK)
        self.cseq += 1
        self.sseq += 1
        self._emit(self.cli, self.srv, self.sport, 502, self.cseq, self.sseq, self.ACK)

    def exchange(self, req: bytes, resp: bytes):
        self._emit(self.cli, self.srv, self.sport, 502, self.cseq, self.sseq, self.PSH | self.ACK, req)
        self.cseq += len(req)
        self._emit(self.srv, self.cli, 502, self.sport, self.sseq, self.cseq, self.PSH | self.ACK, resp)
        self.sseq += len(resp)
        self._emit(self.cli, self.srv, self.sport, 502, self.cseq, self.sseq, self.ACK)

    def close(self):
        self._emit(self.cli, self.srv, self.sport, 502, self.cseq, self.sseq, self.FIN | self.ACK)
        self._emit(self.srv, self.cli, 502, self.sport, self.sseq, self.cseq + 1, self.FIN | self.ACK)
        self._emit(self.cli, self.srv, self.sport, 502, self.cseq + 1, self.sseq + 1, self.ACK)


def build() -> list[bytes]:
    pk: list[bytes] = []
    read_req = struct.pack("!BHH", 3, 0, 4)                    # fc3, addr 0, qty 4
    read_resp = struct.pack("!BB4H", 3, 8, 812, 655, 1, 0)
    hmi = Flow(HMI, PLC, 40100, pk)
    hmi.open()
    hmi.exchange(_mbap(1, read_req), _mbap(1, read_resp))
    hmi.close()
    atk = Flow(ATTACKER, PLC, 51515, pk)
    atk.open()
    atk.exchange(_mbap(1, read_req), _mbap(1, read_resp))
    write = struct.pack("!BHH", 6, 11, 0xDEAD)                 # fc6: matikan pompa
    atk.exchange(_mbap(2, write), _mbap(2, write))
    atk.close()
    return pk


def write_pcap(path: str, packets: list[bytes], t0: int = 1_794_000_000) -> None:
    p = pathlib.Path(path)
    p.parent.mkdir(parents=True, exist_ok=True)
    with open(p, "wb") as f:
        f.write(struct.pack("<IHHiIII", 0xA1B2C3D4, 2, 4, 0, 0, 65535, 1))
        for i, pkt in enumerate(packets):
            f.write(struct.pack("<IIII", t0 + i // 10, (i % 10) * 100_000, len(pkt), len(pkt)))
            f.write(pkt)


if __name__ == "__main__":
    out = sys.argv[1] if len(sys.argv) > 1 else str(
        pathlib.Path(__file__).with_name("pcap") / "serangan-modbus.pcap")
    pkts = build()
    write_pcap(out, pkts)
    print(f"{len(pkts)} paket ditulis ke {out}")
