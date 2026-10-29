# WAYANG

Deception Grid Adaptif untuk Pertahanan IT/OT Satuan TNI AD.
Rancangan acuan: `../WAYANG - Proposal Teknis Kartika Cyber Hackathon 2026.docx` (tidak diubah).

100% defensif. Semua efek tulis pada bayangan bersifat log-only. Tidak ada hack-back.
Pengujian hanya ke bayangan milik sendiri. Satuan, alamat, dan persona adalah simulasi/fiktif.

## Menjalankan

```
pip install -r requirements.txt
python -m pytest tests -q                 # 28 tes
python -m demo --mode full                # 3 satuan simulasi + pusat + konsol → http://127.0.0.1:8080
python sim_attacker/evaluate.py           # ukur lalu tulis docs/hasil_evaluasi.md
docker compose up                         # opsional
```

## Status (fase Purwarupa, Bab 15)

| Komponen | Bab | Status |
|---|---|---|
| Lakon Depo BBM (`lakon/`) | 6.4, 7 | selesai (Lakon lain belum) |
| Telemetri Hidup (`telemetry/`) | 4.1, 8 | selesai |
| Bayangan Modbus (`shadows/modbus_*.py`) | 6.2 | selesai (latensi ekor panjang, kode galat, kedalaman bertingkat) |
| Bayangan HMI Web (`shadows/hmi_web.py`) | 6.2 | selesai (login umpan, tag, honeytoken) |
| Kelir: proxy, skor, Shadow Divert, Cermin Keadaan, gagal-aman | 9.1, 9.4 | selesai untuk Modbus/TCP |
| Mesin Adaptif + anggaran tipuan | 9.2, 9.3 | selesai |
| Pemeta ATT&CK ICS, Generator Aturan (Sigma, STIX, nftables draf) | 9.5 | selesai |
| Antrean persetujuan, blokir, otonomi L0–L3, saklar darurat | 11.1 | selesai |
| Korelasi lintas satuan, Edge Sync store-and-forward | 9.6 | selesai |
| Log berantai-hash, Penyimpan Sesi, putar ulang | 6.2, 9.7 | selesai |
| Dalang Console, Bot Dalang, Berita Acara DOCX/HTML | 9.7, 11 | selesai (UI satu halaman, bukan React/Vite) |
| Bayangan Sosial | 10 | selesai (persona, honeydoc, kanari; belum ada penerima SMTP) |
| Penyerang simulasi + harness evaluasi | 13 | selesai |

Belum: Lakon selain Depo BBM, protokol DNP3/IEC-104/S7, proxy HTTP dengan Shadow Divert,
uji buta penyamaran oleh manusia, kalibrasi bobot dari data nyata.
Detail dan alasan: [docs/arsitektur.md](docs/arsitektur.md). Hasil ukur: [docs/hasil_evaluasi.md](docs/hasil_evaluasi.md).
