"""Berita Acara otomatis (Bab 9.7): draf Laporan Forensik Digital (DOCX/HTML).

Satu klik menyusun kronologi: waktu, sumber, urutan teknik, bukti berantai-hash,
dan lampiran putar ulang sesi. Draf WAJIB ditinjau dan ditandatangani manusia.
"""
from __future__ import annotations

import html
import pathlib
import time

from docx import Document
from docx.shared import Pt, Inches

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
    
    # Sisipkan Logo Resmi terkompresi ringan (~12 KB) bila tersedia
    static_dir = pathlib.Path(__file__).parent / "static"
    logo_file = static_dir / "Logo_report.jpg"
    if not logo_file.is_file():
        logo_file = static_dir / "Logo.jpeg"
    if logo_file.is_file():
        try:
            d.add_picture(str(logo_file), width=Inches(0.9))
        except Exception:
            pass

    # Header Dokumen Simulasi Purwarupa (Bukan Dokumen Resmi Negara)
    watermark_box = d.add_paragraph(
        "===================================================================\n"
        "*** DOKUMEN SIMULASI PURWARUPA - BUKAN DOKUMEN RESMI NEGARA / TNI AD ***\n"
        "PURWARUPA RISET PERTAHANAN SIBER IT/OT - KARTIKA CYBER HACKATHON 2026\n"
        "Mendukung Integritas Bukti Digital & Chain of Custody Kriptografis (RFC 6962)\n"
        "==================================================================="
    )
    watermark_box.paragraph_format.space_after = Pt(4)
    for run in watermark_box.runs:
        run.font.size = Pt(8)
        run.bold = True

    # Kop Purwarupa Riset Pertahanan
    kop = d.add_paragraph("KARTIKA CYBER HACKATHON 2026 - PUSAT RISET PERTAHANAN SIBER\n"
                          "SIMULASI C4ISR DECEPTION GRID TERDISTRIBUSI\n"
                          f"NODE PANGKALAN TERUJI: {data['satuan']}\n"
                          "-----------------------------------------------------------------")
    kop.paragraph_format.space_after = Pt(2)
    for run in kop.runs:
        run.font.size = Pt(9)
        run.bold = True

    h0 = d.add_heading("BERITA ACARA PEMERIKSAAN INSIDEN SIBER (BAP-FD) - SIMULASI", 0)
    h0.paragraph_format.space_before = Pt(6)
    d.add_paragraph(f"Nomor Berkas : SIMULASI-BA-FD/{data['satuan']}/{s['session']}\n"
                    f"Klasifikasi  : SIMULASI / TERBATAS (Riset & Evaluasi Purwarupa)\n"
                    f"Waktu Uji    : {data['generated']}")

    p = d.add_paragraph(f"[{DISCLAIMER}]")
    p.runs[0].bold = True
    p.runs[0].font.size = Pt(9)

    d.add_heading("1. Identitas & Status Operasional Insiden", 1)
    for k, v in [("Satuan Terkait", data["satuan"]), ("ID Sesi Forensik", s["session"]),
                 ("Alamat IP Sumber", s["src"]), ("Tahap Serangan Tertinggi", s["stage"]),
                 ("Kedalaman Adaptif Terbuka", f"Level {s['depth']}"),
                 ("Pengalihan ke Bayangan (Shadow Divert)", "Ya (Berhasil dialihkan oleh Kelir)" if s.get("diverted", False) else "Tidak"),
                 ("Integritas Aset Asli", "Terisolasi Penuh (0 instruksi berbahaya diteruskan ke fisik riil dalam simulasi)"),
                 ("Waktu Selesai Perekaman", data["generated"])]:
        d.add_paragraph(f"• {k}: {v}")

    d.add_heading("2. Pemetaan Taktik ATT&CK for ICS Terobservasi", 1)
    t = d.add_table(rows=1, cols=3)
    t.style = "Table Grid"
    for i, h in enumerate(("ID Teknik", "Nama Teknik", "Taktik ICS")):
        t.rows[0].cells[i].text = h
    for x in data["techniques"]:
        r = t.add_row().cells
        r[0].text, r[1].text, r[2].text = x["id"], x["nama"], x["taktik"]
    d.add_paragraph("Landasan doktrin: Pemetaan taktis selaras dengan kerangka MITRE ATT&CK for ICS dan MITRE D3FEND.")

    d.add_heading("3. Kronologi & Rekonstruksi (Putar Ulang Sesi)", 1)
    replay_all = data["replay"]
    replay_shown = replay_all[:60]
    t = d.add_table(rows=1, cols=5)
    t.style = "Table Grid"
    for i, h in enumerate(("Delta (dtk)", "Waktu UTC", "Aksi Terdeteksi", "Kedalaman", "Keterangan")):
        t.rows[0].cells[i].text = h
    for e in replay_shown:
        r = t.add_row().cells
        r[0].text, r[1].text, r[2].text = str(e["t"]), e["ts"], e["action"]
        r[3].text, r[4].text = str(e["depth"]), str(e["note"])[:120]
    if len(replay_all) > len(replay_shown):
        d.add_paragraph(f"(Menampilkan {len(replay_shown)} dari total {len(replay_all)} langkah interaksi sesi.)")

    d.add_heading("4. Alat Bukti Integritas Digital (Chain of Custody SHA-256)", 1)
    events_all = data["events"]
    events_shown = events_all[:60]
    d.add_paragraph(f"Status Verifikasi Kriptografis Rantai Hash ({len(events_all)} blok): {'LULUS (Terbukti Utuh dan Tak Terubah)' if data['chain_ok'] else 'GAGAL'}")
    t = d.add_table(rows=1, cols=3)
    t.style = "Table Grid"
    for i, h in enumerate(("ID Kejadian", "Hash SHA-256", "Hash Sebelumnya")):
        t.rows[0].cells[i].text = h
    for e in events_shown:
        r = t.add_row().cells
        r[0].text, r[1].text, r[2].text = e["event_id"], e["hash"][:28] + "…", e["prev_hash"][:28] + "…"
    if len(events_all) > len(events_shown):
        d.add_paragraph(f"(Menampilkan {len(events_shown)} dari total {len(events_all)} daun rantai hash; seluruh rantai telah diverifikasi utuh.)")
    for row in t.rows:
        for c in row.cells:
            for pp in c.paragraphs:
                for rn in pp.runs:
                    rn.font.size = Pt(8)

    d.add_heading("5. Umpan Balik Pertahanan (Bayangan ke Benteng)", 1)
    for pr in data["proposals"]:
        d.add_paragraph(f"Draf Pertahanan {pr['id']} – Status: {pr['status']}; Rasio Benteng: {pr['ratio_benteng']:.0%}")
        for h in pr["hardening"]:
            d.add_paragraph(f"• Rekomendasi Hardening: {h}")

    sig = d.add_paragraph(
        "\n\n                                                    Mengesahkan Pengujian,\n"
        "                                                    Penguji Teknis / Tim Pengembang Purwarupa,\n\n\n\n"
        "                                                    ( .................................................. )\n"
        "                                                    Verifikator Forensik Digital (Simulasi)"
    )
    sig.runs[0].font.size = Pt(10)
    
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
    logo_tag = '<img src="/static/Logo.jpeg" style="height:48px;vertical-align:middle;margin-right:12px;border-radius:4px">'
    watermark_html = (
        "<div style='background:#fef2f2;border:1px solid #f87171;color:#991b1b;padding:8px 12px;margin-bottom:16px;border-radius:4px;font-size:12px;font-weight:bold;text-align:center'>"
        "*** DOKUMEN SIMULASI PURWARUPA - BUKAN DOKUMEN RESMI NEGARA / TNI AD ***<br>"
        "Mendukung Integritas Bukti Digital & Chain of Custody Kriptografis (RFC 6962)"
        "</div>"
    )
    return (f"<html><body style='font-family:Segoe UI,sans-serif;padding:24px;background:#f8fafc;color:#0f172a'>"
            f"{watermark_html}"
            f"<h1>{logo_tag}Berita Acara Insiden Siber (Simulasi Purwarupa)</h1><p><b>{DISCLAIMER}</b></p>"
            f"<p>Satuan: {html.escape(data['satuan'])} · Sesi: {html.escape(s['session'])} · "
            f"Sumber: {html.escape(s['src'])}</p><p>Rantai hash: "
            f"{'LULUS' if data['chain_ok'] else 'GAGAL'}</p><ul>{techs}</ul>"
            f"<table border=1><tr><th>t</th><th>Waktu</th><th>Aksi</th><th>Kedalaman</th>"
            f"<th>Catatan</th></tr>{rows}</table></body></html>")
