"""Berita Acara otomatis (Bab 9.7): draf Laporan Forensik Digital (DOCX/HTML).

Satu klik menyusun kronologi: waktu, sumber, urutan teknik, bukti berantai-hash,
dan lampiran putar ulang sesi. Draf WAJIB ditinjau dan ditandatangani manusia.
"""
from __future__ import annotations

import html
import pathlib
import time

from docx import Document
from docx.shared import Pt

DISCLAIMER = ("DRAF OTOMATIS. Dokumen ini disusun sistem dan wajib ditinjau serta "
              "ditandatangani petugas berwenang sebelum menjadi laporan resmi.")


def collect(node, session_id: str) -> dict:
    summ = next((s for s in node.store.sessions() if s["session"] == session_id), None)
    if summ is None:
        raise KeyError(session_id)
    events = node.store.events(session_id)
    verified = node.chain.verify()
    techs = [{"id": t, "nama": node.pipeline.mapper.name(t),
              "taktik": node.pipeline.mapper.tactic(t)} for t in summ["techniques"]]
    props = [p.brief() for p in node.approvals.items.values() if p.session == session_id]
    return {"summary": summ, "events": events, "chain_ok": verified, "techniques": techs,
            "replay": node.store.replay(session_id), "proposals": props,
            "generated": time.strftime("%Y-%m-%d %H:%M:%S"), "satuan": node.satuan}


def build_docx(data: dict, path: str | pathlib.Path) -> pathlib.Path:
    s, d = data["summary"], Document()
    d.add_heading("Berita Acara Insiden Siber (Draf)", 0)
    p = d.add_paragraph(DISCLAIMER)
    p.runs[0].bold = True
    d.add_heading("1. Identitas Insiden", 1)
    for k, v in [("Satuan", data["satuan"]), ("Sesi", s["session"]), ("Sumber", s["src"]),
                 ("Tahap tertinggi", s["stage"]), ("Kedalaman", s["depth"]),
                 ("Dialihkan ke bayangan", "Ya" if s["diverted"] else "Tidak"),
                 ("Aset asli tersentuh", "Tidak (log-only pada bayangan)"),
                 ("Disusun", data["generated"])]:
        d.add_paragraph(f"{k}: {v}")
    d.add_heading("2. Teknik ATT&CK for ICS Terobservasi", 1)
    t = d.add_table(rows=1, cols=3)
    t.style = "Table Grid"
    for i, h in enumerate(("ID", "Nama", "Taktik")):
        t.rows[0].cells[i].text = h
    for x in data["techniques"]:
        r = t.add_row().cells
        r[0].text, r[1].text, r[2].text = x["id"], x["nama"], x["taktik"]
    d.add_paragraph("Catatan: pemetaan ID teknik perlu diverifikasi dengan katalog resmi.")
    d.add_heading("3. Kronologi (Putar Ulang Sesi)", 1)
    t = d.add_table(rows=1, cols=5)
    t.style = "Table Grid"
    for i, h in enumerate(("t (dtk)", "Waktu UTC", "Aksi", "Kedalaman", "Catatan")):
        t.rows[0].cells[i].text = h
    for e in data["replay"]:
        r = t.add_row().cells
        r[0].text, r[1].text, r[2].text = str(e["t"]), e["ts"], e["action"]
        r[3].text, r[4].text = str(e["depth"]), str(e["note"])[:120]
    d.add_heading("4. Bukti Berantai-Hash", 1)
    d.add_paragraph(f"Verifikasi rantai SHA-256: {'LULUS' if data['chain_ok'] else 'GAGAL'}")
    t = d.add_table(rows=1, cols=3)
    t.style = "Table Grid"
    for i, h in enumerate(("Event", "Hash", "Hash sebelumnya")):
        t.rows[0].cells[i].text = h
    for e in data["events"]:
        r = t.add_row().cells
        r[0].text, r[1].text, r[2].text = e["event_id"], e["hash"][:24] + "…", e["prev_hash"][:24] + "…"
    for row in t.rows:
        for c in row.cells:
            for pp in c.paragraphs:
                for rn in pp.runs:
                    rn.font.size = Pt(8)
    d.add_heading("5. Tindak Lanjut Pertahanan", 1)
    for pr in data["proposals"]:
        d.add_paragraph(f"Proposal {pr['id']} – status {pr['status']}; "
                        f"rasio benteng {pr['ratio_benteng']:.0%}")
        for h in pr["hardening"]:
            d.add_paragraph(h, style="List Bullet")
    d.add_paragraph("\n\nMengetahui,\n\n\n(.............................)")
    path = pathlib.Path(path)
    path.parent.mkdir(parents=True, exist_ok=True)
    d.save(path)
    return path


def build_html(data: dict) -> str:
    s = data["summary"]
    rows = "".join(
        f"<tr><td>{e['t']}</td><td>{html.escape(e['ts'])}</td><td>{html.escape(e['action'])}</td>"
        f"<td>{e['depth']}</td><td>{html.escape(str(e['note']))}</td></tr>" for e in data["replay"])
    techs = "".join(f"<li>{x['id']} {html.escape(x['nama'])} ({html.escape(x['taktik'])})</li>"
                    for x in data["techniques"])
    return (f"<html><body><h1>Berita Acara Insiden Siber (Draf)</h1><p><b>{DISCLAIMER}</b></p>"
            f"<p>Satuan: {html.escape(data['satuan'])} · Sesi: {html.escape(s['session'])} · "
            f"Sumber: {html.escape(s['src'])}</p><p>Rantai hash: "
            f"{'LULUS' if data['chain_ok'] else 'GAGAL'}</p><ul>{techs}</ul>"
            f"<table border=1><tr><th>t</th><th>Waktu</th><th>Aksi</th><th>Kedalaman</th>"
            f"<th>Catatan</th></tr>{rows}</table></body></html>")
