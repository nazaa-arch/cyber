# Arsitektur Implementasi WAYANG

Mengikuti proposal (Bab 6, 9, 11). Dokumen proposal tidak diubah; berikut pemetaan ke kode.

```
Penyerang/Operator ──► Kelir (kelir/proxy.py) ──► Aset asli  (hanya sesi sah / bacaan tak mencurigakan)
                          │  skor sesi (kelir/scoring.py, kelir/session.py)
                          │  pin sesi ──► Bayangan Modbus (shadows/modbus_shadow.py)
                          │                    ▲ Cermin Keadaan satu arah (kelir/mirror.py)
Penyerang langsung ──────────────────► Bayangan Modbus / Bayangan HMI (shadows/hmi_web.py)
                          ▼ Gamelan (engine/gamelan.py)
        Pipeline (engine/pipeline.py): Pemeta ATT&CK ► Log berantai-hash ► Penyimpan Sesi (SQLite)
              ► Generator Aturan ► Antrean Persetujuan ► Bot Dalang ► Edge Sync ► Pusat (korelasi)
```

| Bab | Kemampuan | Kode |
|---|---|---|
| 4.1 P1 | Telemetri Hidup | `telemetry/models.py` |
| 4.1 P2, 9.2, 9.3 | Kedalaman Adaptif, anggaran tipuan, pembekuan saat uji konsistensi | `engine/adaptive.py`, `shadows/modbus_shadow.py` |
| 4.1 P3, 9.4 | Shadow Divert, Cermin Keadaan, gagal-aman | `kelir/proxy.py`, `kelir/mirror.py` |
| 4.1 P4, 9.5 | Siklus Bayangan ke Benteng | `engine/rulegen.py`, `engine/approval.py` |
| 4.1 P5, 9.6 | Korelasi lintas satuan | `engine/fingerprint.py`, `console/pusat.py`, `console/edge_sync.py` |
| 9.7 | Berita Acara otomatis (DOCX/HTML) | `console/report.py` |
| 10 | Bayangan Sosial | `engine/social.py` |
| 11 | Dalang Console, Bot Dalang | `console/api.py`, `console/static/`, `console/bot.py` |
| 11.1 | Otonomi L0–L3, saklar darurat | `engine/autonomy.py` |
| 14 | Hash-chain, isolasi | `evidence/hashchain.py`, `docker-compose.yml` |

## Keputusan implementasi (dan alasannya)
- **Modbus ditulis langsung di atas asyncio** (`shadows/modbus_proto.py`), bukan `pymodbus`:
  Kelir harus mem-parsing frame per transaksi dan mengontrol kode kesalahan secara presisi.
- **Dalang Console memakai satu halaman HTML + Leaflet + ECharts** yang dibundel lokal
  (`console/static/`) agar jalan di jaringan air-gapped. Proposal menyebut React/Vite;
  fungsi panel sama, kerangka UI bisa dimigrasikan tanpa mengubah API. Peta tanpa ubin
  (tidak butuh internet).
- **Bot Dalang**: kanal internal bawaan; `TelegramChannel` tersedia tetapi belum diuji
  terhadap API Telegram sungguhan.
- **Kampanye**: k=3 satuan lewat kemiripan sidik jari (Bab 9.6). Bukti honeytoken lintas
  satuan menjadi bukti pasti dan cukup 2 satuan, sesuai skenario Bab 12 (Kodim-03 → Kodim-05).
- **L0/L1 meneruskan lalu lintas apa adanya** dan hanya mencatat `would_divert`, sesuai
  tabel Bab 11.1 ("Mencatat dan menampilkan"). Ini berarti pada L0/L1 penulisan dari sumber
  tak terdaftar ikut ke aset asli; untuk perlindungan gunakan L2 (bawaan).
- **Pengalihan HTTP**: Kelir saat ini meng-proxy Modbus/TCP. Bayangan HMI Web melayani
  alamatnya sendiri (sentuhan langsung); proxy HTTP dengan pin sesi belum dibuat.
- **Peracunan data**: proposal per sumber dibatasi 3 dan tidak pernah diterapkan otomatis.
- Nilai awal bobot skor, V dan R mesin adaptif adalah tebakan ahli; Bab 9.3 menyatakan
  harus dikalibrasi dari data uji.

## Batas yang diketahui
- ID teknik ATT&CK for ICS di `engine/attck_ics.yaml` perlu diverifikasi dengan katalog resmi.
- Hanya Lakon Depo BBM yang matang. Lakon Gerbang/CCTV, Genset, Server Administrasi,
  Radio IP, dan protokol DNP3/IEC-104/S7 belum dibuat (Fase "Perluasan protokol").
- Penyamaran terhadap penyerang T3 tidak dijamin (Bab 4.2) dan uji buta manusia belum dijalankan.
- Penerapan blokir pada prototipe diwujudkan sebagai daftar blokir di Kelir; `nftables`
  tetap berupa draf berkas yang tidak dieksekusi sistem.
