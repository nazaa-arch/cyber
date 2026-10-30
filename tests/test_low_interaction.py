import asyncio
import sys, pathlib
sys.path.insert(0, str(pathlib.Path(__file__).resolve().parents[1]))

import pytest
from engine.gamelan import Gamelan
from shadows.low_interaction import LowInteractionICSListener


def test_low_interaction_ics_listeners():
    async def go():
        bus = Gamelan()
        events = []
        bus.subscribe(events.append)

        listener = LowInteractionICSListener("Kodim-TEST", bus, host="127.0.0.1")
        ports = await listener.start()
        try:
            assert "iec104" in ports
            assert "opcua" in ports
            assert "dnp3" in ports

            # 1. Test IEC-104 STARTDT ACT probe
            r, w = await asyncio.open_connection("127.0.0.1", ports["iec104"])
            # Kirim frame U STARTDT ACT (68 04 07 00 00 00)
            w.write(bytes([0x68, 0x04, 0x07, 0x00, 0x00, 0x00]))
            await w.drain()
            resp = await asyncio.wait_for(r.read(6), timeout=2.0)
            assert resp == bytes([0x68, 0x04, 0x0B, 0x00, 0x00, 0x00])  # STARTDT CONFIRM
            w.close()

            # 2. Test OPC UA Hello probe
            r, w = await asyncio.open_connection("127.0.0.1", ports["opcua"])
            w.write(b"HEL" + bytes(28))
            await w.drain()
            resp = await asyncio.wait_for(r.read(4), timeout=2.0)
            assert resp == b"ACKF"
            w.close()

            # 3. Test DNP3 probe
            r, w = await asyncio.open_connection("127.0.0.1", ports["dnp3"])
            w.write(bytes([0x05, 0x64, 0x05, 0xC0, 0x01, 0x00, 0x00, 0x00, 0x00, 0x00]))
            await w.drain()
            resp = await asyncio.wait_for(r.read(10), timeout=2.0)
            assert len(resp) == 10
            assert resp[:2] == bytes([0x05, 0x64])
            w.close()

            # Verifikasi bahwa semua probe terekam di bus Gamelan
            probe_protos = {e["proto"] for e in events if e.get("action") == "ics_protocol_probe"}
            assert "iec104" in probe_protos
            assert "opcua" in probe_protos
            assert "dnp3" in probe_protos
        finally:
            listener.close()

    asyncio.run(go())
