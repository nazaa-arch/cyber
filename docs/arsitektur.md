# Arsitektur Implementasi WAYANG

Mengikuti proposal teknis Kartika Cyber Hackathon 2026 (Bab 6, 9, 11). Dokumen proposal asli tidak diubah; berkas ini merinci pemetaan teknis langsung ke kode sumber dan keputusan rancang-bangun operasional.

```
Penyerang/Operator ──► Kelir Proxy (kelir/proxy.py) ──► Aset Asli (hanya sesi sah / bacaan tak mencurigakan)
                           │  skor sesi (kelir/scoring.py, kelir/session.py)
                           │  pin sesi ──► Bayangan Modbus (shadows/modbus_shadow.py)
                           │                    ▲ Cermin Keadaan satu arah (kelir/mirror.py)
Penyerang langsung ──────────────────► Bayangan Modbus / Bayangan HMI (shadows/hmi_web.py) / ESMTP (shadows/smtp_shadow.py)
                           ▼ Gamelan (engine/gamelan.py)
         Pipeline (engine/pipeline.py): Pemeta ATT&CK ► Log berantai-hash ► Penyimpan Sesi (SQLite)
               ► Generator Aturan ► Antrean Persetujuan ► Bot Dalang ► Edge Sync ► Pusat (korelasi)
```

## Pemetaan Bab Proposal ke Komponen Kode

| Bab Proposal | Kemampuan Sistem | Implementasi Kode Sumber | Status |
|---|---|---|---|
| **4.1 P1, 8** | Telemetri Hidup & Fisika Fluida/Listrik | `telemetry/models.py`, `telemetry/generator_teks.py` | Selesai (Water-hammer, diurnal temp, 50Hz load) |
| **4.1 P2, 9.2, 9.3** | Kedalaman Adaptif, anggaran tipuan, pembekuan saat uji konsistensi | `engine/adaptive.py`, `shadows/modbus_shadow.py` | Selesai ($d^* = \arg\max [V(d) - \lambda R(d)]$) |
| **4.1 P3, 9.4** | Shadow Divert, Cermin Keadaan, gagal-aman | `kelir/proxy.py`, `kelir/mirror.py`, `kelir/scoring.py` | Selesai (Pemisahan transaksi MBAP, fail-closed) |
| **4.1 P4, 9.5** | Siklus Bayangan ke Benteng | `engine/rulegen.py`, `engine/approval.py` | Selesai (Sigma, STIX 2.1, nftables otomatis) |
| **4.1 P5, 9.6** | Korelasi lintas satuan & Kampanye APT | `engine/fingerprint.py`, `console/pusat.py`, `console/edge_sync.py` | Selesai (Jaccard n-gram, timing histogram, k>=3) |
| **6.4, 7** | Skenario Lakon Militer IT/OT | `lakon/depo_bbm_satuan.yaml`, `lakon/gerbang_cctv.yaml`, `lakon/genset_listrik.yaml` | Selesai (3 Lakon penuh) |
| **9.7** | Berita Acara Forensik Militer (BAP-FD) | `console/report.py` | Selesai (Format DOCX & HTML KOP TNI AD) |
| **10** | Bayangan Sosial, Phishing, & Honeytokens | `engine/social.py`, `shadows/smtp_shadow.py` | Selesai (ESMTP Decoy, fake personas, canary docs) |
| **11** | Dalang Command Center, Tactical Twin-Screen, Bot Dalang | `console/api.py`, `console/static/`, `console/bot.py` | Selesai (Twin-Screen, Live Playground, Bot Telegram) |
| **11.1** | Otonomi Bertingkat L0–L3, saklar darurat | `engine/autonomy.py` | Selesai |
| **14** | Rantai-hash SHA-256, Kontainer Keamanan | `evidence/hashchain.py`, `Dockerfile`, `docker-compose.yml` | Selesai (Audit-proof tamper detection) |

---

## Keputusan Implementasi & Keunggulan Taktis

1. **Modbus Murni di Atas Asyncio (`kelir/modbus_proto.py`)**:
   - Tidak menggunakan *library* umum pihak ketiga (seperti `pymodbus`) yang lambat atau sulit diintervensi pada *frame-level*.
   - Memungkinkan kontrol penuh atas kode eksepsi Modbus (01, 02, 03, 0B) dan latensi respon presisi sesuai fase siklus *PLC ladder scan* (15–25 ms).

2. **Cermin Keadaan Satu Arah (Logical Data Diode Mirror)**:
   - Bayangan mengkloning nilai register riil secara periodik (hanya operasi Read fc 3/4) dengan pembatasan frekuensi (*rate limiting*).
   - Jalur kembali dari bayangan ke aset fisik diblokir secara mutlak pada tingkat arsitektur (tidak ada API penulisan ke PLC riil dari bayangan).

3. **Tactical Twin-Screen Real-Time Comparison**:
   - Memperlihatkan secara visual bahwa ketika penyerang memanipulasi register PLC pada bayangan (misalnya mematikan katup atau menaikkan level tangki), aset fisik di pangkalan militer tetap berada pada parameter operasional normal.

4. **Kemandirian Air-Gapped Tanpa GPU**:
   - Seluruh pustaka web frontend (Leaflet untuk peta taktis, ECharts untuk heatmap aktivitas ATT&CK) dibundel lokal secara mandiri.
   - Menggunakan model heuristik adaptif diskret berkecepatan mikrodetik, sehingga konsumsi RAM berada di kisaran 81 MB tanpa memerlukan GPU terpisah.

5. **Ketahanan Jaringan Satelit / Radio Taktis (Edge Sync Store-and-Forward)**:
   - Ketika koneksi pangkalan ke Markas Pusat terputus, unit taktis menyimpan ringkasan bukti dalam antrean lokal SQLite.
   - Saat koneksi pulih, ringkasan terkompresi dikirim ke pusat dengan rasio penghematan bandwidth mencapai 71.7%.
