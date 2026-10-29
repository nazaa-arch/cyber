"""Deep Packet Inspection (DPI) & Sidik Jari Alat Penyerang ICS (OT Forensic Analyzer).

Menganalisis frame Modbus/TCP dan protokol industri secara mendalam untuk:
- Mengidentifikasi alat ofensif: Metasploit, Nmap NSE, PLCscan, atau Custom APT
- Menghasilkan representasi hex-dump untuk inspektur paket C4ISR
- Menghitung anomali struktural header MBAP
"""
from __future__ import annotations

import struct
import time
from typing import Dict, Any, List, Optional


class OffensiveToolFingerprinter:
    """Mengidentifikasi jenis alat serang dari karakteristik frame dan pola transaksi."""

    @staticmethod
    def inspect_frame(raw_bytes: bytes, src_ip: str) -> Dict[str, Any]:
        """Membedah frame Modbus/TCP mentah (MBAP Header + PDU)."""
        hex_dump = " ".join(f"{b:02X}" for b in raw_bytes)
        ascii_dump = "".join(chr(b) if 32 <= b <= 126 else "." for b in raw_bytes)

        res: Dict[str, Any] = {
            "src_ip": src_ip,
            "raw_len": len(raw_bytes),
            "hex_dump": hex_dump,
            "ascii_dump": ascii_dump,
            "tool_detected": "Trafik Normal",
            "anomaly_level": "LOW",
            "mbap": {},
            "pdu": {}
        }

        if len(raw_bytes) < 7:
            res["anomaly_level"] = "CRITICAL (MALFORMED)"
            return res

        # Bedah MBAP Header (7 bytes)
        # Transaction ID (2B), Protocol ID (2B), Length (2B), Unit ID (1B)
        tid, proto_id, length, uid = struct.unpack(">HHHB", raw_bytes[:7])
        pdu = raw_bytes[7:]

        fc = pdu[0] if len(pdu) > 0 else 0
        res["mbap"] = {
            "transaction_id": tid,
            "protocol_id": proto_id,
            "length": length,
            "unit_id": uid
        }
        res["pdu"] = {
            "function_code": fc,
            "pdu_len": len(pdu),
            "payload_hex": " ".join(f"{b:02X}" for b in pdu[1:]) if len(pdu) > 1 else ""
        }

        # 1. Deteksi Nmap modbus-discover.nse
        # Nmap kerap mengirim fc 43 (MEI Read Device Identification) atau Unit ID 0 atau 255
        if fc == 43 or uid in (0, 255):
            res["tool_detected"] = "Nmap (modbus-discover.nse)"
            res["anomaly_level"] = "HIGH"

        # 2. Deteksi Metasploit SCADA Scanner
        # Modul Metasploit auxiliary/scanner/scada/modbusclient mengirim pembacaan berulang
        elif proto_id == 0 and fc in (1, 2, 3, 4) and length == 6 and tid in (0, 1):
            res["tool_detected"] = "Metasploit ICS Framework"
            res["anomaly_level"] = "HIGH"

        # 3. Deteksi Sabotase Fisik APT (Unauthorized Write)
        # Upaya memaksakan perintah tulis pada koil atau register penampung bahaya
        elif fc in (5, 6, 15, 16):
            res["tool_detected"] = "Targeted APT Industrial Sabotage"
            res["anomaly_level"] = "CRITICAL"

        # 4. Deteksi PLCscan / Reconnaissance Script
        elif len(pdu) >= 5 and fc in (1, 3):
            addr, cnt = struct.unpack(">HH", pdu[1:5])
            if cnt > 100 or addr > 65000:
                res["tool_detected"] = "Automated ICS Fuzzer / Scanner"
                res["anomaly_level"] = "MEDIUM"

        return res


class PacketInspectorStore:
    """Penyimpan ringkas riwayat paket untuk modal inspektur paket C4ISR."""

    def __init__(self, max_packets: int = 100):
        from collections import deque
        self.packets: deque = deque(maxlen=max_packets)

    def record(self, raw_bytes: bytes, src_ip: str, satuan: str) -> Dict[str, Any]:
        info = OffensiveToolFingerprinter.inspect_frame(raw_bytes, src_ip)
        packet_record = {
            "id": f"PKT-{int(time.time() * 1000) % 100000:05d}",
            "ts": time.time(),
            "satuan": satuan,
            **info
        }
        self.packets.appendleft(packet_record)
        return packet_record

    def get_recent(self, limit: int = 30) -> List[Dict[str, Any]]:
        return list(self.packets)[:limit]
