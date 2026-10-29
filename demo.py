"""Demo terpadu WAYANG.

  python -m demo --mode full      3 satuan simulasi + pusat + Dalang Console + penyerang
  python -m demo --mode console   hanya konsol dengan satu satuan simulasi
  python -m demo --mode node      satu node (Kelir + bayangan + HMI) di atas aset asli simulasi

Semua satuan, alamat, dan persona adalah SIMULASI/FIKTIF.
"""
from __future__ import annotations

import argparse
import asyncio
import os
import pathlib
import tempfile

# Muat konfigurasi .env lokal bila ada
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
from sim_attacker.modbus_client import ModbusClient
from sim_attacker.real_sim import RealDeviceSim

UNITS = [("Kodim-DEMO-03", 3, -6.92, 107.61), ("Kodim-DEMO-05", 5, -7.80, 110.37),
         ("Kodim-DEMO-07", 7, -7.25, 112.75)]


async def build(host: str, base_port: int, out: str):
    pusat = Pusat(Correlator(k_satuan=3, window_s=3600))
    link = Link(pusat)
    nodes, reals = {}, []
    for i, (name, seed, lat, lon) in enumerate(UNITS):
        real = RealDeviceSim()
        rs = await real.serve("127.0.0.1", 0)
        reals.append(rs)
        n = SatuanNode(name, seed, ("127.0.0.1", rs.sockets[0].getsockname()[1]),
                       str(pathlib.Path(out) / name), {"10.0.0.5"}, time_scale=60,
                       transport=link, host=host, lab_mode=True,
                       ports=(base_port + i * 10, base_port + i * 10 + 1, base_port + i * 10 + 2))
        pusat.register_unit(name, lat, lon)
        await n.start()
        nodes[name] = n
    if "Kodim-DEMO-03" in nodes:
        pusat.bot = nodes["Kodim-DEMO-03"].bot
    return pusat, nodes, reals


async def attack_story(nodes: dict) -> None:
    """Skenario satu malam (Bab 12), diputar ke bayangan milik sendiri."""
    n3 = nodes["Kodim-DEMO-03"]
    await sc.t1_opportunist("127.0.0.1", n3.ports["shadow"], "127.0.0.9")
    await sc.t2_targeted("127.0.0.1", n3.ports["kelir"], "127.0.0.10")
    for n in nodes.values():
        n.sync()


def _detect_public_url() -> str | None:
    explicit = os.environ.get("CONSOLE_URL")
    if explicit:
        return explicit
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


async def amain(a):
    if a.mode == "realtime":
        import run_wayang
        await run_wayang.amain(a)
        return

    out = a.out or tempfile.mkdtemp(prefix="wayang_")
    pub = _detect_public_url()
    if pub:
        os.environ["CONSOLE_URL"] = pub
        print(f"[PUBLIC URL] Dalang Console (ngrok): {pub}")
    pusat, nodes, _ = await build(a.host, a.base_port, out)
    if a.mode == "full":
        await attack_story(nodes)
    for n in nodes.values():
        n.edge.flush()
    app = make_console_app(nodes, pusat)
    print(f"Dalang Console: http://{a.host}:{a.port}   keluaran: {out}")
    await uvicorn.Server(uvicorn.Config(app, host=a.host, port=a.port, log_level="warning")).serve()


def main():
    ap = argparse.ArgumentParser()
    ap.add_argument("--mode", choices=["realtime", "full", "console", "node"], default="realtime")
    ap.add_argument("--host", default="127.0.0.1")
    ap.add_argument("--port", type=int, default=8080)
    ap.add_argument("--base-port", type=int, default=15020)
    ap.add_argument("--out", default=None)
    asyncio.run(amain(ap.parse_args()))


if __name__ == "__main__":
    main()
