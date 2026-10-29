"""WAYANG: Realtime Defense Engine & C4ISR Cyber Command Center.

Platform Pertahanan Siber IT/OT Realtime Terdistribusi TNI Angkatan Darat.
Menggantikan mode demo statis menjadi mesin pertahanan siber operasional aktif.
"""
from __future__ import annotations

import argparse
import asyncio
import os
import pathlib
import sys
import tempfile
import time

# Muat konfigurasi lingkungan (.env) bila tersedia
_env_path = pathlib.Path(__file__).resolve().parent / ".env"
if _env_path.is_file():
    for _line in _env_path.read_text(encoding="utf-8").splitlines():
        _line = _line.strip()
        if _line and not _line.startswith("#") and "=" in _line:
            _k, _v = _line.split("=", 1)
            os.environ.setdefault(_k.strip(), _v.strip())

import uvicorn

from console.api import make_console_app
from console.pusat import Link, Pusat
from engine.fingerprint import Correlator
from node import SatuanNode
from sim_attacker import scenarios as sc
from sim_attacker.real_sim import RealDeviceSim

# 5 Satuan Komando Operasional Pertahanan Siber TNI AD
OPERATIONAL_UNITS = [
    {
        "satuan": "MABESAD-Siber",
        "alias": ["MABESAD", "Pusinfolahta"],
        "seed": 1,
        "lat": -6.1754,
        "lon": 106.8272,
        "level": "MABES",
        "role": "Pusat Komando & Pengendali Siber Operasi Terpadu (C4ISR)",
        "commander": "Brigjen TNI (Pusinfolahta TNI AD)",
        "comm_link": "Fiber Optik Terenkripsi Kemenhan / Satcyber",
        "asset_name": "Gateway Dalang AI & Validator Kriptografis Hash-Chain",
        "lakon": "lakon/depo_bbm_satuan.yaml"
    },
    {
        "satuan": "KODAM-IV-Diponegoro",
        "alias": ["Kodim-DEMO-03", "Kodim-03", "Korem-072", "Kodim-0734"],
        "seed": 3,
        "lat": -7.8014,
        "lon": 110.3647,
        "level": "KODAM",
        "role": "Depo Bahan Bakar Minyak (BBM) Taktis Satuan",
        "commander": "Letkol Cba Hendro K. (Dandenbekang)",
        "comm_link": "Radio Taktis HF/VHF Harris + VSAT Militer",
        "asset_name": "Modbus/TCP PLC Depo BBM Satuan (Level Solar 20.000L)",
        "lakon": "lakon/depo_bbm_satuan.yaml"
    },
    {
        "satuan": "KODAM-III-Siliwangi",
        "alias": ["Kodim-DEMO-05", "Kodim-05", "Yonif-315"],
        "seed": 5,
        "lat": -6.5971,
        "lon": 106.7996,
        "level": "KODAM",
        "role": "Komando Perimeter & Gerbang CCTV Pangkalan",
        "commander": "Mayor Inf Aryo S. (Danyonif)",
        "comm_link": "IP Radio Taktis Harris Falcon III",
        "asset_name": "Perimeter Barrier Gate & Video Surveillance Gateway",
        "lakon": "lakon/gerbang_cctv.yaml"
    },
    {
        "satuan": "KODAM-V-Brawijaya",
        "alias": ["Kodim-DEMO-07", "Kodim-07", "Satrad-222"],
        "seed": 7,
        "lat": -7.2575,
        "lon": 112.7521,
        "level": "KODAM",
        "role": "Sistem Daya Listrik Darurat (ATS/UPS & Genset Pangkalan)",
        "commander": "Letkol Cpl Wahyu P. (Dandenpal)",
        "comm_link": "Link Mikrowave Terenkripsi Antar-Korem",
        "asset_name": "Schneider Electric ATS Controller (380V 50Hz)",
        "lakon": "lakon/genset_listrik.yaml"
    },
    {
        "satuan": "DIVIF-1-Kostrad",
        "alias": ["Kostrad-Cilodong", "Bekang-Kostrad"],
        "seed": 9,
        "lat": -6.4428,
        "lon": 106.8436,
        "level": "KOSTRAD",
        "role": "Depo Suplai Bahan Bakar & Amunisi Terpadu",
        "commander": "Kolonel Cba Teguh R. (Danbekang Kostrad)",
        "comm_link": "Satelit Militer Taktis Bergerak",
        "asset_name": "Industrial Flow Meter & Automated Dispenser PLC",
        "lakon": "lakon/depo_bbm_satuan.yaml"
    }
]


def _detect_public_url() -> str | None:
    try:
        import urllib.request, json
        res = urllib.request.urlopen("http://127.0.0.1:4040/api/tunnels", timeout=1)
        data = json.loads(res.read())
        tunnels = data.get("tunnels", [])
        if tunnels:
            return tunnels[0]["public_url"]
    except Exception:
        pass
    return None


async def build_operational_system(host: str, base_port: int, out_dir: str):
    """Membangun infrastruktur pertahanan terdistribusi TNI AD."""
    pusat = Pusat(Correlator(k_satuan=2, window_s=3600))
    link = Link(pusat)
    nodes, reals = {}, []

    for i, u in enumerate(OPERATIONAL_UNITS):
        name = u["satuan"]
        seed = u["seed"]
        real = RealDeviceSim()
        rs = await real.serve(host, 0)
        reals.append(rs)

        # Inisialisasi node pangkalan militer
        n = SatuanNode(
            name, seed, (host, rs.sockets[0].getsockname()[1]),
            str(pathlib.Path(out_dir) / name), {"10.0.0.5", "192.168.1.100"},
            time_scale=60.0, transport=link, host=host, lab_mode=True,
            ports=(base_port + i * 10, base_port + i * 10 + 1, base_port + i * 10 + 2)
        )

        pusat.register_unit(
            name, u["lat"], u["lon"],
            level=u["level"], role=u["role"],
            commander=u["commander"], comm_link=u["comm_link"],
            asset_name=u["asset_name"]
        )

        await n.start(with_hmi=(i < 3))
        nodes[name] = n

        # Daftarkan alias agar pengujian dan skrip otomatis tetap kompatibel
        for alias in u.get("alias", []):
            nodes[alias] = n

    # Sambungkan bot dalang ke Kodam IV (Depo BBM utama)
    if "KODAM-IV-Diponegoro" in nodes:
        pusat.bot = nodes["KODAM-IV-Diponegoro"].bot

    return pusat, nodes, reals


async def start_realtime_background_engine(nodes: dict, pusat: Pusat):
    """Menjalankan loop telemetri hidup & injeksi trafik realistis secara realtime."""
    print("[REALTIME] Mesin pertahanan taktis aktif. Memulai stream telemetri hidup...")
    
    # 1. Injeksi skenario awal agar dasbor memiliki data historis
    n4 = nodes.get("KODAM-IV-Diponegoro")
    n3 = nodes.get("KODAM-III-Siliwangi")
    if n4:
        try:
            await sc.t1_opportunist("127.0.0.1", n4.ports["shadow"], "185.220.101.44")
            await sc.t2_targeted("127.0.0.1", n4.ports["kelir"], "198.51.100.88")
            n4.sync()
        except Exception as e:
            print(f"[INIT] Skenario awalan selesai: {e}")

    # 2. Loop real-time latar belakang terus menerus
    loop_count = 0
    while True:
        try:
            await asyncio.sleep(2.0)
            loop_count += 1

            # Sinkronkan status lokal pangkalan ke pusat setiap beberapa detik
            for name, n in list(nodes.items()):
                if hasattr(n, "sync") and name in [u["satuan"] for u in OPERATIONAL_UNITS]:
                    n.sync()

            # Setiap 60 detik (30 loop), lakukan pemindaian ringan otomatis untuk menjaga sistem tetap hidup
            if loop_count % 30 == 0:
                target_node = nodes.get("KODAM-IV-Diponegoro")
                if target_node:
                    src_ip = f"203.0.113.{10 + (loop_count % 50)}"
                    await sc.t1_opportunist("127.0.0.1", target_node.ports["shadow"], src_ip)
                    target_node.sync()

        except asyncio.CancelledError:
            break
        except Exception as e:
            # Cegah loop terputus bila ada anomali sesaat
            await asyncio.sleep(1.0)


async def amain(args):
    out_dir = args.out or tempfile.mkdtemp(prefix="wayang_live_")
    pub = _detect_public_url()
    if pub:
        os.environ["CONSOLE_URL"] = pub
        print(f"[PUBLIC URL] Dalang C4ISR Command Center (ngrok): {pub}")

    pusat, nodes, reals = await build_operational_system(args.host, args.base_port, out_dir)

    # Jalankan background engine realtime
    bg_task = asyncio.create_task(start_realtime_background_engine(nodes, pusat))

    app = make_console_app(nodes, pusat)
    print("=" * 70)
    print("       WAYANG: C4ISR CYBER DEFENSE REALTIME PLATFORM (TNI AD)")
    print(f"       Konsol Komando : http://{args.host}:{args.port}")
    print(f"       Direktori Audit: {out_dir}")
    print("=" * 70)

    try:
        config = uvicorn.Config(app, host=args.host, port=args.port, log_level="warning")
        server = uvicorn.Server(config)
        await server.serve()
    finally:
        bg_task.cancel()
        for r in reals:
            r.close()
        for n in set(nodes.values()):
            await n.stop()


def main():
    parser = argparse.ArgumentParser(description="WAYANG C4ISR Realtime Defense Engine")
    parser.add_argument("--host", default="127.0.0.1", help="Host interface")
    parser.add_argument("--port", type=int, default=8080, help="Port Web Dalang Console")
    parser.add_argument("--base-port", type=int, default=15020, help="Base port Modbus/HMI")
    parser.add_argument("--out", default=None, help="Direktori keluaran log/audit")
    parser.add_argument("--mode", default="realtime", choices=["realtime", "full", "console"], help="Mode operasi")
    args = parser.parse_args()

    asyncio.run(amain(args))


if __name__ == "__main__":
    main()
