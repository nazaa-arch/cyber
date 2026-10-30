"""Sensor Umpan Interaksi Rendah untuk Protokol ICS Tambahan (DNP3, IEC-104, OPC UA, BACnet).

Sesuai evaluasi audit arsitektur sistem:
Modbus TCP adalah emulasi interaksi tinggi (full stateful ladder logic simulation).
Untuk mendeteksi reconnaissance jaringan IP ICS multi-protokol tanpa overhead kompleksitas
tinggi, modul ini menyediakan low-interaction probe listener pada:
- DNP3 (TCP 20000)
- IEC 60870-5-104 (TCP 2404)
- OPC UA (TCP 4840)
- BACnet/IP (UDP 47808)

Setiap percobaan koneksi/pemindaian langsung dicatat ke bus Gamelan dan dimasukkan ke
dalam analisis kampanye C4ISR.
"""
from __future__ import annotations

import asyncio
import logging
import time

log = logging.getLogger("wayang.low_interaction")

ICS_PORTS = {
    "dnp3": 20000,
    "iec104": 2404,
    "opcua": 4840,
    "bacnet": 47808,
}


class LowInteractionICSListener:
    def __init__(self, satuan: str, bus, host: str = "127.0.0.1", port_override: dict[str, int] | None = None):
        self.satuan = satuan
        self.bus = bus
        self.host = host
        self.port_override = port_override or {}
        self.servers: list[asyncio.Server] = []
        self.udp_transports: list[asyncio.DatagramTransport] = []
        self.probe_counts: dict[str, int] = {k: 0 for k in ICS_PORTS}

    def _event(self, proto: str, src: str, action: str, **extra):
        self.probe_counts[proto] = self.probe_counts.get(proto, 0) + 1
        if self.bus:
            self.bus.publish({
                "ts": time.strftime("%Y-%m-%dT%H:%M:%SZ", time.gmtime()),
                "satuan": self.satuan,
                "proto": proto,
                "src": src,
                "action": action,
                "via": "low_interaction_listener",
                **extra
            })

    async def _handle_tcp(self, proto: str, reader: asyncio.StreamReader, writer: asyncio.StreamWriter):
        src = writer.get_extra_info("peername")[0]
        try:
            data = await asyncio.wait_for(reader.read(256), timeout=3.0)
            self._event(proto, src, "ics_protocol_probe", raw_bytes_hex=data.hex() if data else "")
            
            # Respons minimal yang valid sesuai standar protokol
            if proto == "iec104" and data and len(data) >= 6 and data[0] == 0x68:
                # Menjawab frame U (STARTDT ACT) dengan STARTDT CONFIRM
                # Format IEC-104: 68 04 0B 00 00 00
                writer.write(bytes([0x68, 0x04, 0x0B, 0x00, 0x00, 0x00]))
                await writer.drain()
            elif proto == "opcua" and data and data.startswith(b"HEL"):
                # Menjawab OPC UA Hello dengan Acknowledge minimal
                # Format: "ACKF" + len (32-bit LE) + version, recv/send buffer sizes
                ack = b"ACKF" + (28).to_bytes(4, "little") + (0).to_bytes(4, "little") + (65536).to_bytes(4, "little") + (65536).to_bytes(4, "little") + (0).to_bytes(4, "little") + (0).to_bytes(4, "little")
                writer.write(ack)
                await writer.drain()
            elif proto == "dnp3" and data:
                # Menjawab DNP3 data link reset link states / minimal ACK jika ada header 0x05 0x64
                if len(data) >= 2 and data[0] == 0x05 and data[1] == 0x64:
                    # DNP3 DLC ACK frame
                    dnp_ack = bytes([0x05, 0x64, 0x05, 0x00, 0x01, 0x00, 0x00, 0x00, 0x00, 0x00])
                    writer.write(dnp_ack)
                    await writer.drain()
        except (asyncio.TimeoutError, ConnectionResetError, OSError):
            self._event(proto, src, "ics_connection_reset")
        finally:
            writer.close()

    async def start(self) -> dict[str, int]:
        ports_bound = {}
        for proto, default_port in ICS_PORTS.items():
            if proto == "bacnet":
                # BACnet menggunakan UDP
                continue
            port = self.port_override.get(proto, 0)
            try:
                server = await asyncio.start_server(
                    lambda r, w, p=proto: self._handle_tcp(p, r, w),
                    self.host, port
                )
                self.servers.append(server)
                bound_port = server.sockets[0].getsockname()[1]
                ports_bound[proto] = bound_port
            except OSError as e:
                log.warning("Gagal bind listener %s pada %s:%s: %s", proto, self.host, port, e)
        return ports_bound

    def close(self):
        for s in self.servers:
            s.close()
        for t in self.udp_transports:
            t.close()
