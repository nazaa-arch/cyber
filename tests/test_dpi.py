"""Unit test untuk Deep Packet Inspection & Sidik Jari Alat Penyerang."""
import struct
from kelir.dpi import OffensiveToolFingerprinter, PacketInspectorStore


def test_dpi_nmap_detection():
    # Buat frame Modbus FC 43 (MEI) khas Nmap
    # MBAP: tid=1, proto=0, len=6, uid=255, PDU: fc=43, mei_type=14, read_device_id=1, obj_id=0, pad=0
    raw = struct.pack(">HHHBBBBBB", 1, 0, 6, 255, 43, 14, 1, 0, 0)
    res = OffensiveToolFingerprinter.inspect_frame(raw, "192.168.1.50")

    assert res["tool_detected"] == "Nmap (modbus-discover.nse)"
    assert res["anomaly_level"] == "HIGH"
    assert res["mbap"]["unit_id"] == 255


def test_dpi_apt_write_sabotage():
    # Buat frame Modbus FC 06 (Write Single Register)
    # MBAP: tid=10, proto=0, len=6, uid=1, PDU: fc=6, addr=30001, val=9999
    raw = struct.pack(">HHHBBHH", 10, 0, 6, 1, 6, 30001, 9999)
    res = OffensiveToolFingerprinter.inspect_frame(raw, "185.220.101.5")

    assert res["tool_detected"] == "Targeted APT Industrial Sabotage"
    assert res["anomaly_level"] == "CRITICAL"
    assert "hex_dump" in res
    assert "ascii_dump" in res


def test_packet_inspector_store():
    store = PacketInspectorStore(max_packets=5)
    raw = struct.pack(">HHHBBH", 1, 0, 4, 1, 3, 100)
    rec = store.record(raw, "10.0.0.5", "KODAM-IV")

    assert rec["satuan"] == "KODAM-IV"
    assert len(store.get_recent()) == 1
