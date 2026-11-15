"""Demo alur integrasi di satu laptop: Suricata -> WAYANG -> Wazuh.

1. Ambil alert Suricata ASLI dari integrations/lab/out/eve.json (hasil `suricata -r`
   atas pcap lab). Karena demo berjalan di loopback, IP penyerang di alert itu
   dipetakan ke 127.0.0.1 dan ditulis ke eve-demo.json (ditandai jelas).
2. Jalankan SatuanNode asli dengan WAYANG_SURICATA_EVE dan WAYANG_WAZUH_LOG.
3. Penyerang (127.0.0.1) membaca lalu menulis register pompa lewat Kelir.
4. Cetak: tanda IDS, keputusan Kelir, isi PLC asli, dan baris untuk Wazuh.

Pakai (dari folder wayang/):  python integrations/lab/demo_alur.py
"""
from __future__ import annotations

import asyncio
import json
import os
import pathlib
import struct
import sys
import tempfile

ROOT = pathlib.Path(__file__).resolve().parents[2]
sys.path.insert(0, str(ROOT))
LAB = pathlib.Path(__file__).resolve().parent
OUT = LAB / "out"


def prepare_eve() -> pathlib.Path:
    src = OUT / "eve.json"
    if not src.exists():
        sys.exit("eve.json belum ada. Jalankan Suricata atas pcap lab dulu (lihat docker-compose.yml).")
    alerts = [json.loads(l) for l in src.read_text(encoding="utf-8").splitlines()
              if '"event_type":"alert"' in l]
    if not alerts:
        sys.exit("eve.json tidak berisi alert.")
    demo = OUT / "eve-demo.json"
    with open(demo, "w", encoding="utf-8") as f:
        for a in alerts:
            a["src_ip"] = "127.0.0.1"
            a["x_wayang_demo"] = "src_ip dipetakan dari 10.10.5.90 ke loopback untuk demo satu laptop"
            f.write(json.dumps(a) + "\n")
    return demo


async def main() -> None:
    eve = prepare_eve()
    wz = OUT / "wayang-alerts.json"
    if wz.exists():
        wz.unlink()
    os.environ["WAYANG_SURICATA_EVE"] = str(eve)
    os.environ["WAYANG_IDS_FROM_START"] = "1"
    os.environ["WAYANG_WAZUH_LOG"] = str(wz)
    os.environ.pop("TELEGRAM_BOT_TOKEN", None)

    from node import SatuanNode
    from shadows import modbus_proto as mp
    from sim_attacker.real_sim import RealDeviceSim

    real = RealDeviceSim()
    rs = await real.serve("127.0.0.1", 0)
    rport = rs.sockets[0].getsockname()[1]
    node = SatuanNode("Kodim-DEMO-03", 3, ("127.0.0.1", rport), tempfile.mkdtemp(),
                      whitelist={"127.0.0.2"}, time_scale=60)
    node.kelir.zero_trust = False          # buktikan pengalihan datang dari tanda Suricata
    await node.start(with_hmi=False)
    node.eve.poll()
    print("[1] Tanda Suricata :", [(h.ip, h.sid, h.signature) for h in node.ids.active()])

    r, w = await asyncio.open_connection("127.0.0.1", node.ports["kelir"])
    for tid, pdu in ((1, mp.build_read_request(3, 0, 2)), (2, struct.pack(">BHH", 6, 11, 0xDEAD))):
        w.write(mp.build_mbap(tid, 1, pdu))
        await w.drain()
        await asyncio.wait_for(mp.read_frame(r), 3)
    w.close()
    await asyncio.sleep(0.2)

    div = [a for a in node.pipeline.alerts if a["kind"] in ("ids", "divert", "diverted_write")]
    print("[2] Alert konsol   :")
    for a in div:
        print("     -", a["kind"], "|", a["text"][:120])
    print("[3] Tulis ke PLC asli:", len(real.writes), "(harus 0)")
    lines = wz.read_text(encoding="ascii").splitlines() if wz.exists() else []
    print(f"[4] {len(lines)} baris untuk Wazuh di {wz}:")
    for l in lines:
        rec = json.loads(l)
        print("     -", rec["wayang"]["action"], rec["srcip"], rec["wayang"].get("mitre_ics", ""))
    print("[5] Rantai hash utuh:", node.pipeline.verify_chain())
    await node.stop()
    rs.close()


if __name__ == "__main__":
    asyncio.run(main())
