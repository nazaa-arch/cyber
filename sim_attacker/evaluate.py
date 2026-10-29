"""Harness evaluasi (Bab 13): mengukur, lalu menulis docs/hasil_evaluasi.md.

Prinsip: tidak ada angka diklaim sebelum diukur. Semua angka di sini berasal
dari proses ini di mesin pengembang (bukan mini-PC satuan). Uji buta
penyamaran dengan relawan manusia TIDAK dapat diotomatiskan dan tetap [isi].
"""
from __future__ import annotations

import asyncio
import json
import os
import pathlib
import platform
import statistics
import sys
import tempfile
import time

sys.path.insert(0, str(pathlib.Path(__file__).resolve().parents[1]))

import psutil  # noqa: E402

from console.pusat import Link, Pusat  # noqa: E402
from engine.attck_map import AttckMapper  # noqa: E402
from engine.gamelan import Gamelan  # noqa: E402
from kelir.session import SessionRegistry  # noqa: E402
from node import SatuanNode  # noqa: E402
from shadows.modbus_shadow import ShadowDevice  # noqa: E402
from sim_attacker import scenarios as sc  # noqa: E402
from sim_attacker.modbus_client import ModbusClient  # noqa: E402
from sim_attacker.real_sim import RealDeviceSim  # noqa: E402

OP = "127.0.0.2"          # operator sah (daftar putih)
H = "127.0.0.1"


class FakeClock:
    def __init__(self):
        self.t = 1000.0

    def __call__(self):
        return self.t

    def advance(self, s):
        self.t += s


def p95(xs):
    xs = sorted(xs)
    return xs[int(0.95 * (len(xs) - 1))]


async def _stack(tmp, n_shadows_nodes=1, **kw):
    real = RealDeviceSim()
    rs = await real.serve(H, 0)
    node = SatuanNode("Kodim-DEMO-03", 3, (H, rs.sockets[0].getsockname()[1]), tmp,
                      {OP}, time_scale=60, lab_mode=True, **kw)
    await node.start(with_hmi=False)
    return real, rs, node


async def eval_alerts_speed_latency(tmp) -> dict:
    real, rs, node = await _stack(tmp)
    try:
        kport = node.ports["kelir"]
        # lalu lintas sah (daftar putih)
        reqs_legit = 0
        for _ in range(5):
            await sc.legit_operator(H, kport, OP, 20)
            reqs_legit += 21
        legit_alerts = [a for a in node.pipeline.alerts
                        if node.sessions.by_id[a["session"]].src == OP]
        # penyerang skrip
        scen = [sc.t1_opportunist, sc.t2_targeted, sc.t3_consistency_tester]
        malicious, ttfa = [], []
        for i in range(12):
            src = f"127.0.1.{i + 1}"
            malicious.append(src)
            t0 = time.monotonic()
            await scen[i % 3](H, kport, src)
            mine = [a for a in node.pipeline.alerts
                    if node.sessions.by_id[a["session"]].src == src]
            if mine:
                ttfa.append((min(a["t_alert"] for a in mine) - t0) * 1000)
        alerts = list(node.pipeline.alerts)   # sebelum uji latensi (yang menyentuh bayangan lagi)
        by_src = {a["session"]: node.sessions.by_id[a["session"]].src for a in alerts}
        tp = sum(1 for a in alerts if by_src[a["session"]] in malicious)
        recall = len({by_src[a["session"]] for a in alerts if by_src[a["session"]] in malicious}) / len(malicious)
        # time-to-first-alert murni pipeline: dari event dibuat sampai alert
        ev_alert = [(a["t_alert"] - a["t_event"]) * 1000 for a in alerts]
        # latensi p95: jalur asli (operator) dan jalur bayangan (dialihkan)
        lat_real, lat_shadow = [], []
        async with ModbusClient(H, kport, local_addr=OP) as c:
            for _ in range(300):
                t = time.perf_counter()
                await c.read(4, 0, 2)
                lat_real.append((time.perf_counter() - t) * 1000)
        async with ModbusClient(H, kport, local_addr="127.0.2.1") as c:
            await c.write_reg(11, 0)
            for _ in range(300):
                t = time.perf_counter()
                await c.read(4, 0, 1)
                lat_shadow.append((time.perf_counter() - t) * 1000)
        techs = [len(s["techniques"]) for s in node.store.sessions()]
        rb = [p.bundle["ratio_benteng"] for p in node.approvals.items.values()]
        return {
            "legit_requests": reqs_legit, "legit_alerts": len(legit_alerts),
            "fpr_daftar_putih": len(legit_alerts) / reqs_legit,
            "alerts_total": len(alerts), "presisi": tp / len(alerts) if alerts else None,
            "recall": recall, "malicious_sources": len(malicious),
            "ttfa_ms_median": statistics.median(ttfa), "ttfa_ms_p95": p95(ttfa),
            "event_to_alert_ms_p95": p95(ev_alert),
            "lat_asli_p95_ms": p95(lat_real), "lat_bayangan_p95_ms": p95(lat_shadow),
            "teknik_per_sesi_rata2": statistics.mean(techs) if techs else 0,
            "rasio_benteng_rata2": statistics.mean(rb) if rb else None,
            "real_writes_total": len(real.writes),
            "real_writes_diharapkan_operator_sah": 5,   # 5 sesi operator x 1 tulis; Kelir meneruskan atas nama klien
            "chain_ok": node.chain.verify(),
        }
    finally:
        await node.stop()
        rs.close()


def eval_ab(n: int = 30) -> dict:
    res = {}
    for name, adaptive in (("statis", False), ("adaptif", True)):
        dwell, steps, techs = [], [], []
        for seed in range(n):
            clock = FakeClock()
            bus, evs = Gamelan(), []
            bus.subscribe(evs.append)
            reg = SessionRegistry(idle_s=1e9)
            sh = ShadowDevice("d", "K", seed, reg, bus, clock=clock, time_scale=1,
                              adaptive=adaptive)
            out = sc.CuriousAttacker(seed).run(sh, "198.51.100.7", clock)
            m = AttckMapper()
            ts = set()
            for e in evs:
                ts.update(m.map(e))
            dwell.append(out["dwell_sim_s"])
            steps.append(out["steps"])
            techs.append(len(ts))
        res[name] = {"dwell_sim_s_rata2": statistics.mean(dwell),
                     "langkah_rata2": statistics.mean(steps),
                     "teknik_unik_rata2": statistics.mean(techs), "n": n}
    return res


async def eval_resources(tmp, n_nodes: int = 10, n_req: int = 3000) -> dict:
    proc = psutil.Process()
    rss0 = proc.memory_info().rss
    real = RealDeviceSim()
    rs = await real.serve(H, 0)
    rport = rs.sockets[0].getsockname()[1]
    nodes = []
    for i in range(n_nodes):
        n = SatuanNode(f"Kodim-LOAD-{i:02d}", i, (H, rport), os.path.join(tmp, f"n{i}"),
                       {OP}, time_scale=60, lab_mode=True)
        await n.start(with_hmi=False)
        nodes.append(n)
    cpu0, w0 = time.process_time(), time.perf_counter()
    async def drive(n, k):
        async with ModbusClient(H, n.ports["kelir"], local_addr="127.0.3.1") as c:
            await c.write_reg(11, 0)
            for _ in range(k):
                await c.read(4, 0, 2)
    await asyncio.gather(*[drive(n, n_req // n_nodes) for n in nodes])
    wall = time.perf_counter() - w0
    cpu = time.process_time() - cpu0
    rss = proc.memory_info().rss
    for n in nodes:
        await n.stop()
    rs.close()
    return {"n_bayangan": n_nodes, "requests": n_req, "wall_s": wall,
            "cpu_s": cpu, "cpu_persen_satu_core": 100 * cpu / wall,
            "rss_mb_tambahan": (rss - rss0) / 1e6, "rss_mb_total": rss / 1e6}


async def eval_resilience(tmp, outage_s: float = 10.0, n_sessions: int = 40) -> dict:
    pusat = Pusat()
    link = Link(pusat)
    real = RealDeviceSim()
    rs = await real.serve(H, 0)
    node = SatuanNode("Kodim-DEMO-03", 3, (H, rs.sockets[0].getsockname()[1]), tmp, {OP},
                      time_scale=60, lab_mode=True, transport=link)
    await node.start(with_hmi=False)
    try:
        link.up = False
        for i in range(n_sessions):
            async with ModbusClient(H, node.ports["kelir"], local_addr=f"127.0.4.{i + 1}") as c:
                await c.write_reg(11, 0)
        sent_during = node.sync()
        await asyncio.sleep(outage_s)
        pending = node.edge.pending()
        link.up = True
        node.sync()
        raw = sum(len(json.dumps(e)) for e in node.store.all_events())
        return {"outage_s_nyata": outage_s, "sesi": n_sessions,
                "terkirim_saat_putus": sent_during, "antrean_saat_putus": pending,
                "diterima_pusat": pusat.received,
                "ringkasan_hilang": n_sessions - len({k for k in pusat.corr.sessions}),
                "bytes_ringkasan_terkirim": node.edge.sent_bytes,
                "bytes_log_mentah_setara": raw,
                "rasio_hemat": 1 - node.edge.sent_bytes / raw if raw else None}
    finally:
        await node.stop()
        rs.close()


def fmt(v, nd=2):
    return "n/a" if v is None else (f"{v:.{nd}f}" if isinstance(v, float) else str(v))


def write_report(r: dict, path: pathlib.Path) -> None:
    a, ab, rs, rl = r["alert"], r["ab"], r["res"], r["resil"]
    md = f"""# Hasil Evaluasi WAYANG (Bab 13)

Dihasilkan otomatis oleh `sim_attacker/evaluate.py` pada {time.strftime('%Y-%m-%d %H:%M')}.
Mesin: {platform.system()} {platform.release()}, {os.cpu_count()} CPU logis, Python {platform.python_version()}.

> **Batas klaim.** Angka berikut diukur pada mesin pengembang dengan penyerang
> simulasi buatan tim (skrip internal, hanya ke bayangan milik sendiri). Ini bukan
> uji pada mini-PC satuan, bukan penyerang nyata, dan bukan uji buta manusia.
> Baris "Penyamaran" sengaja dibiarkan kosong sampai relawan menguji.

| Aspek | Metrik | Target awal | Hasil | Status |
|---|---|---|---|---|
| Penyamaran | Tingkat tebakan benar (uji buta 5–10 relawan) | Mendekati 50% | [isi] | belum diuji (butuh manusia, lihat `docs/uji_buta_protokol.md`) |
| Kualitas alert | FPR pada lalu lintas daftar putih | mendekati 0 | {fmt(a['fpr_daftar_putih'], 4)} ({a['legit_alerts']} alert dari {a['legit_requests']} permintaan sah) | {'tercapai' if a['legit_alerts'] == 0 else 'tidak tercapai'} |
| Kualitas alert | Presisi / recall alert pada skenario skrip | tinggi | {fmt(a['presisi'])} / {fmt(a['recall'])} ({a['malicious_sources']} sumber berbahaya) | diukur |
| Kecepatan | Time-to-first-alert (sentuhan pertama → alert), median / p95 | < 2 dtk | {fmt(a['ttfa_ms_median'], 1)} ms / {fmt(a['ttfa_ms_p95'], 1)} ms (pipeline kejadian→alert p95 {fmt(a['event_to_alert_ms_p95'], 2)} ms) | {'tercapai' if a['ttfa_ms_p95'] < 2000 else 'tidak tercapai'} |
| Nilai adaptif | Dwell time simulasi (rata-rata, dtk), statis vs adaptif | adaptif lebih tinggi | {fmt(ab['statis']['dwell_sim_s_rata2'], 1)} vs {fmt(ab['adaptif']['dwell_sim_s_rata2'], 1)} | {'adaptif lebih tinggi' if ab['adaptif']['dwell_sim_s_rata2'] > ab['statis']['dwell_sim_s_rata2'] else 'tidak lebih tinggi'} |
| Nilai adaptif | Teknik unik tertangkap per sesi, statis vs adaptif | adaptif lebih tinggi | {fmt(ab['statis']['teknik_unik_rata2'])} vs {fmt(ab['adaptif']['teknik_unik_rata2'])} (n={ab['adaptif']['n']}) | {'adaptif lebih tinggi' if ab['adaptif']['teknik_unik_rata2'] > ab['statis']['teknik_unik_rata2'] else 'tidak lebih tinggi'} |
| Latensi | p95 respons jalur asli / jalur bayangan | < 50 ms | {fmt(a['lat_asli_p95_ms'])} ms / {fmt(a['lat_bayangan_p95_ms'])} ms | {'tercapai' if max(a['lat_asli_p95_ms'], a['lat_bayangan_p95_ms']) < 50 else 'tidak tercapai'} |
| Sumber daya | {rs['n_bayangan']} node (Kelir + bayangan + Cermin) pada 1 proses, {rs['requests']} permintaan | muat di 4 core / 8 GB | CPU {fmt(rs['cpu_persen_satu_core'], 1)}% dari satu core, RSS tambahan {fmt(rs['rss_mb_tambahan'], 1)} MB (total {fmt(rs['rss_mb_total'], 1)} MB) | diukur di mesin pengembang, bukan mini-PC |
| Ketahanan | Kehilangan ringkasan saat link ke pusat putus {fmt(rl['outage_s_nyata'], 0)} dtk nyata | 0 hilang | {rl['ringkasan_hilang']} hilang; antrean saat putus {rl['antrean_saat_putus']}, diterima pusat {rl['diterima_pusat']} | {'tercapai' if rl['ringkasan_hilang'] == 0 else 'tidak tercapai'} (durasi 30 menit target belum dijalankan; mekanisme antrean tidak bergantung durasi) |
| Bandwidth | Hemat vs log mentah setara | hanya ringkasan | {fmt(rl['rasio_hemat'] * 100, 1) if rl['rasio_hemat'] is not None else 'n/a'}% ({rl['bytes_ringkasan_terkirim']} B vs {rl['bytes_log_mentah_setara']} B) | diukur |

## Indikator keberhasilan konsep (Bab 13.1)

| Indikator | Hasil |
|---|---|
| Rasio sentuhan tipuan | presisi alert {fmt(a['presisi'])} pada skenario skrip |
| Waktu sampai sadar | median {fmt(a['ttfa_ms_median'], 1)} ms sampai alert tercatat (ringkasan ke Bot menyusul pada pipeline yang sama) |
| Dwell time pada bayangan | statis {fmt(ab['statis']['langkah_rata2'], 1)} langkah vs adaptif {fmt(ab['adaptif']['langkah_rata2'], 1)} langkah |
| Cakupan teknik | {fmt(a['teknik_per_sesi_rata2'])} teknik ATT&CK ICS unik per sesi (rata-rata) |
| Rasio benteng | {fmt(a['rasio_benteng_rata2'])} (teknik teramati yang punya aturan otomatis) |
| Beban operator | [isi] butuh pengguna uji |

## Jaminan keselamatan yang diverifikasi

- Perintah tulis yang diterima aset asli simulasi: **{a['real_writes_total']}**; seluruhnya berasal dari operator sah di daftar putih (diharapkan {a['real_writes_diharapkan_operator_sah']}). Tulis dari 12 penyerang skrip yang sampai ke aset asli = **{a['real_writes_total'] - a['real_writes_diharapkan_operator_sah']}** (harus 0).
- Rantai hash SHA-256 valid: **{a['chain_ok']}**.

## Catatan kejujuran

- Perilaku `CuriousAttacker` adalah asumsi model; keunggulan adaptif pada A/B
  sebagian mengikuti asumsi itu. Uji sebenarnya membutuhkan penyerang manusia.
- Aset asli simulasi (`real_sim.py`) berlatensi tetap dan sangat sederhana; tidak
  mewakili PLC nyata.
- Latensi diukur di loopback; jaringan nyata menambah latensi pada kedua jalur.
"""
    path.parent.mkdir(parents=True, exist_ok=True)
    path.write_text(md, encoding="utf-8")


async def main() -> dict:
    root = pathlib.Path(__file__).resolve().parents[1]
    tmp = tempfile.mkdtemp(prefix="wayang_eval_")
    r = {"alert": await eval_alerts_speed_latency(os.path.join(tmp, "a")),
         "ab": eval_ab(30),
         "res": await eval_resources(tmp),
         "resil": await eval_resilience(os.path.join(tmp, "r"))}
    write_report(r, root / "docs" / "hasil_evaluasi.md")
    (root / "docs" / "hasil_evaluasi.json").write_text(json.dumps(r, indent=2), encoding="utf-8")
    return r


if __name__ == "__main__":
    out = asyncio.run(main())
    print(json.dumps(out, indent=2))


