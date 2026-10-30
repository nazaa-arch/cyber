# WAYANG: Deception Grid Adaptif untuk Pertahanan IT/OT Satuan TNI AD

[![CI/CD Pipeline](https://github.com/nazaa-arch/cyber/actions/workflows/ci.yml/badge.svg)](https://github.com/nazaa-arch/cyber/actions/workflows/ci.yml)
[![Tests Passing](https://img.shields.io/badge/tests-34%2F34%20passed-brightgreen.svg)]()
[![Zero Real Writes](https://img.shields.io/badge/physical%20safety-0%20real%20writes%20(sim)-blue.svg)]()
[![Detection TTFA](https://img.shields.io/badge/TTFA-1.5ms%20(loopback%20median)-orange.svg)]()
[![Memory Footprint](https://img.shields.io/badge/RAM-81.2%20MB-purple.svg)]()
[![Cryptography RFC 6962](https://img.shields.io/badge/Merkle%20Proof-RFC%206962%20Compliant-blueviolet.svg)]()
[![License](https://img.shields.io/badge/License-Apache%202.0-green.svg)](LICENSE)
[![Live Dashboard](https://img.shields.io/badge/Live%20C4ISR-cyber.steamcraft.online-gold.svg)](https://cyber.steamcraft.online/)

> **Doktrin Pertahanan**: 100% defensif. Menerapkan prinsip isolasi *fail-safe* ke panggung bayangan. Zero hack-back. Sesuai proposal teknis resmi: `WAYANG - Proposal Teknis Kartika Cyber Hackathon 2026.docx`.

---

## 🌐 Akses Sistem Operasional (Live Cloud 24/7)
- **Konsol Komando Utama (C4ISR)**: [https://cyber.steamcraft.online/](https://cyber.steamcraft.online/)
- **Backend Cloud Deployment (Render SG)**: [https://wayang-c4isr.onrender.com/](https://wayang-c4isr.onrender.com/)

---

## 🛡️ Ringkasan Eksekutif

**WAYANG** adalah kerangka kerja *Adaptive Deception Grid* berbasis edge yang dirancang untuk melindungi infrastruktur komando, logistik, dan sistem kendali industri (ICS/SCADA) pada pangkalan **TNI Angkatan Darat**.

Berbeda dengan honeypot tradisional yang pasif dan mudah di-sidik jari (*fingerprinted*) oleh aktor ancaman tingkat lanjut (APT), WAYANG mengintegrasikan proxy transparan lapisan aplikasi (**Kelir**), model fisika dinamis hidup (**Living Telemetry**), pengalihan sesi cerdas (**Shadow Divert**), serta transmisi keadaan satu arah (**Logical Data Diode State Mirror**). Interaksi berbahaya penyerang dialihkan ke lingkungan umpan berlapis tanpa menyadari bahwa mereka telah terisolasi, sementara aset fisik riil tetap beroperasi di jalurnya secara terisolasi.

```
                          ┌────────────────────────┐
                          │   Trafik Jaringan      │
                          │ (Operator / Penyerang) │
                          └───────────┬────────────┘
                                      │
                                      ▼
                        ┌───────────────────────────┐
                        │      KELIR PROXY          │
                        │ - Penilaian Sesi (5-Skor) │
                        │ - Fail-Closed Isolation   │
                        └──────┬─────────────┬──────┘
                               │             │
              [Skor < 0.5 & Terdaftar]       │ [Skor >= 0.5 atau Tak Terdaftar]
                               │             │
                               ▼             ▼
                     ┌──────────────────┐  (Polling Cermin)  ┌───────────────────────────────────┐
                     │    ASET ASLI     │───────────────────►│         BAYANGAN (DECOY)          │
                     │  (PLC / SCADA)   │  Satu Arah         │ - Modbus Decoy + Ladder Timing    │
                     │                  │                    │ - HMI Web SCADA Decoy             │
                     │  Jalur Operasi   │                    │ - ESMTP Decoy & Honeytokens       │
                     └──────────────────┘                    └─────────────────┬─────────────────┘
                                                                               │
                                                                               ▼
                                                             ┌───────────────────────────────────┐
                                                             │           MESIN ADAPTIF           │
                                                             │ - Optimalisasi Kedalaman          │
                                                             │ - Pemetaan MITRE ATT&CK ICS       │
                                                             │ - Hash-Chain SHA-256 (RFC 6962)   │
                                                             └─────────────────┬─────────────────┘
                                                                               │
                                                                               ▼
                                                             ┌───────────────────────────────────┐
                                                             │   SIKLUS BAYANGAN KE BENTENG      │
                                                             │ - Sigma & STIX 2.1 IOC            │
                                                             │ - Draf nftables Perimeter         │
                                                             │ - Dalang Console & Telegram       │
                                                             │ - Berita Acara Forensik (BAP-FD)  │
                                                             └───────────────────────────────────┘
```

---

## 🌟 Keunggulan Utama & Fitur Rekayasa

### 1. Prinsip Desain Zero-Physical-Write (Fail-Safe Decoy Isolation)
- Menggunakan arsitektur **Kelir Modbus Proxy** dengan mitigasi kegagalan *fail-closed*.
- Trafik pemindaian dan manipulasi dari entitas tak dikenal dialihkan secara transparan (*Shadow Divert*) ke bayangan PLC virtual.
- Teruji pada skenario evaluasi simulasi: **0 perintah tulis penyerang yang diteruskan ke simulator aset riil**.

> **Catatan Batasan Keamanan & Asumsi Daftar Putih IP (*IP is Not Identity*)**:
> Berdasarkan prinsip *Zero Trust*, alamat IP bukanlah pembuktian identitas absolut. Jika workstation operator terdaftar dikompromikan oleh penyerang (misal melalui *lateral movement* malware), paket dari IP tersebut dapat mencapai PLC riil. Untuk memitigasi risiko ini:
> 1. Perintah tulis dari IP terdaftar tetap divalidasi format PDU-nya dan dibatasi hanya pada register kendali terdefinisi.
> 2. Seluruh aktivitas penulisan dicatat secara permanen dalam rantai audit Merkle untuk audit forensik.
> 3. Pengembangan ke depan disarankan mengintegrasikan autentikasi kriptografis tingkat aplikasi (seperti *Modbus/TCP Security* atau mTLS).

### 2. High-Fidelity Physics & Scan-Cycle Timing Emulation
- **Physics Fidelity**: Mensimulasikan dinamika fisik fluida (efek *water hammer* saat katup pipa ditutup mendadak, siklus suhu tangki BBM diurnal, serta fluktuasi beban frekuensi 50 Hz pada genset).
- **PLC Scan-Cycle Emulation**: Bayangan merespons Modbus dengan penundaan berbasis siklus scan tangga PLC riil (15–25 ms fase siklus), meminimalisir kemungkinan penyerang membedakan honeypot melalui *TCP kernel turnaround time*.

### 3. Tiga Skenario Lakon Satuan Militer Operasional
1. **Lakon 1: Depo BBM Satuan (`lakon/depo_bbm_satuan.yaml`)**:
   - Telemetri level tangki solar, katup pipa masuk/keluar, pompa transfer, dan sensor tekanan pipa dengan mitigasi transien fluida.
2. **Lakon 2: Gerbang Pangkalan & CCTV NVR (`lakon/gerbang_cctv.yaml`)**:
   - Kontrol barrier gate, status kamera perimeter, umpan kredensial administratif (`admin:admin`), serta *honeytoken* berkas konfigurasi firmware tiruan.
3. **Lakon 3: Genset Listrik & ATS Pangkalan (`lakon/genset_listrik.yaml`)**:
   - Sistem transfer daya otomatis (ATS/UPS), telemetri frekuensi 50 Hz, voltase 380V 3-fasa, dan level tangki harian genset darurat.

### 4. Bayangan Sosial & Umpan Phishing (ESMTP Decoy)
- Menyediakan *fake personas* (Pejabat Logistik Satuan, Perwira Jaga).
- Dokumen kedinasan ber-kanari (canary token embedded).
- Decoy server ESMTP (`shadows/smtp_shadow.py`) yang menangkap surat elektronik phishing penyerang tanpa meneruskannya ke jaringan pangkalan.

### 5. Tactical Twin-Screen C4ISR Console & Uji Taktis
- **Tactical Twin-Screen**: Memvisualisasikan perbandingan *side-by-side* secara *real-time* antara kondisi Aset Fisik Riil vs Bayangan Umpan yang dimanipulasi penyerang.
- **Uji Taktis Terintegrasi**: Tombol simulasi serangan terintegrasi ([T1] Recon Scan, [T2] Shadow Divert, [APT] Kampanye Terpadu, [Canary] Persona, dan Lockdown Satuan) untuk demonstrasi interaktif.

### 6. Dukungan Integritas Chain of Custody Forensik Digital (BAP-FD)
- Setiap event dienkapsulasi dalam **Pohon Merkle RFC 6962** dengan *Root Hash* SHA-256 dan *HMAC Signature* pangkalan.
- Menghasilkan berkas **Berita Acara Pemeriksaan Forensik Digital (BAP-FD)** format `.docx` dan `.html` yang memuat rantai bukti tamper-proof. Dokumen purwarupa dilengkapi penanda tegas `[SIMULASI PURWARUPA - BUKAN DOKUMEN RESMI NEGARA]` untuk mencegah penyalahgunaan administratif.

---

## 📊 Hasil Uji & Benchmark Evaluasi (Bab 13)

Hasil pengukuran berikut diperoleh melalui modul evaluasi `sim_attacker/evaluate.py` dan perbandingan target formal pada Proposal Teknis:

| Parameter Evaluasi | Target Proposal Teknis | Target Internal Desain | Hasil Terukur | Keterangan & Metodologi |
|---|---|---|---|---|
| **Waktu Peringatan Pertama (TTFA)** | < 2.000 ms (< 2 dtk) | < 100 ms | **1.50 ms** (median) / **2.26 ms** (p95) | Terpenuhi. Diukur pada level loopback proxy decision. Pipeline kejadian ke alert p95 = 7.07 ms; pengiriman alert ke Web HUD / Bot ~45–120 ms. |
| **False Positive Rate (FPR)** | Mendekati 0 | 0.0% | **0.0%** (105/105 sukses) | Terpenuhi pada skenario berskrip internal (permintaan operator sah di daftar putih). |
| **Presisi & Recall Deteksi** | Tinggi | 1.0 / 1.0 | **1.0 (100%) / 1.0 (100%)** | Terukur pada skenario berskrip (12 sumber berbahaya sintetis internal). |
| **Dwell Time Penyerang (Adaptif)** | — | Adaptif > Statis | **+48.7%** (27.5s vs 18.5s) | Peningkatan durasi interaksi skrip penyerang otomatis (`CuriousAttacker`) pada bayangan adaptif dibandingkan statis. |
| **Perintah Tulis Tembus ke Fisik** | 0 perintah | 0 penulisan | **0 penulisan** | 5/5 penulisan operator sah diterima; 0/12 penulisan penyerang simulasi mencapai aset riil. |
| **Latensi Respons (p95 Overhead)** | < 50 ms | < 30 ms | **16.30 ms** (asli) / **46.54 ms** (bayangan) | Terpenuhi. Overhead proxy tetap berada jauh di bawah ambang batas toleransi Modbus RTU/TCP (100 ms). |
| **Ketahanan Putus Link (WAN)** | 0 data hilang | 100% store-and-forward | **0 data hilang** | 40 ringkasan terantre saat link putus 10 detik, 100% diterima pusat saat koneksi pulih via antrean SQLite. |
| **Penghematan Bandwidth Taktis** | — | > 50% vs raw log | **71.7%** rasio reduksi | Ringkasan terkompresi (14.601 bytes vs 51.657 bytes raw log mentah setara). |
| **Penggunaan Memori (RAM)** | — | < 256 MB (mini-PC) | **81.2 MB** total RSS | 10 node operasional pada 1 proses, melayani 3.000 permintaan Modbus pada mesin pengujian. |
| **Uji Buta Penyamaran Protokol** | Mendekati 50% (acak) | Indistinguishable | *Protokol Siap Diuji* | Membutuhkan 5–10 penguji manusia independen sesuai panduan pada `docs/uji_buta_protokol.md`. |

> **Catatan Kejujuran Metodologi & Generalisasi**:
> Evaluasi berskrip internal di atas membuktikan integritas logika perangkat lunak dan model matematika sistem. Untuk membuktikan generalisasi di luar skrip internal, sistem juga diuji secara *unscripted* menggunakan pemindai Modbus pihak ketiga independen (`nmap --script modbus-discover`, `mbpoll`, dan klien pihak ketiga `pymodbus`). Pada seluruh pengujian pihak ketiga tersebut, Kelir secara otomatis membelokkan seluruh penelusuran register ke Panggung Bayangan tanpa kebocoran banner atau kegagalan sistem.

---

## 🚀 Panduan Memulai Cepat (Quick Start)

### Persyaratan Sistem
- Python 3.10, 3.11, 3.12, atau 3.13.
- Sistem Operasi: Linux, Windows, atau macOS.
- Ringan: Dapat dijalankan pada mini-PC / laptop taktis tanpa dependensi GPU.

### 1. Kloning & Instalasi Dependensi
```bash
git clone https://github.com/nazaa-arch/cyber.git
cd cyber
pip install -r requirements.txt
```

### 2. Menjalankan Seluruh Pengujian Otomatis (34 Unit & Integration Tests)
```bash
python -m pytest tests -q -p no:warnings
```
*Output diharapkan: `34 passed in ~2.5s (100%)`.*

### 3. Menjalankan Konsol Komando C4ISR (Lokal)
Pada Windows:
```cmd
start_demo.bat
```
Atau via terminal:
```bash
python run_wayang.py --port 8080
```
Buka peramban di: **`http://127.0.0.1:8080`**

### 4. Menjalankan via Docker / Container
```bash
docker compose up -d
```

---

## 🎮 Panduan Demonstrasi Live Hackathon (Skenario 3 Menit)

1. Buka antarmuka komando di **[https://cyber.steamcraft.online/](https://cyber.steamcraft.online/)** (atau `http://127.0.0.1:8080` lokal).
2. Tunjukkan **DEFCON Threat Meter**, jam militer WIB/UTC, dan status koneksi live WebSocket (`WSS 0ms`).
3. Pada panel **Tactical Twin-Screen**:
   - Di sisi kiri: **Aset Fisik Riil** (Depo BBM KODAM IV Diponegoro dengan pompa aktif dan tangki 10.000 L).
   - Di sisi kanan: **Panggung Bayangan** (Decoy Sandbox).
4. Klik tombol **`[T2] Shadow Divert`**:
   - Di Panggung Bayangan, penyerang mematikan pompa (impeller berhenti dan berstatus NON-AKTIF).
   - Di Aset Nyata sebelah kiri, pompa fisik tetap menyala normal dan tangki tidak terpengaruh (*Doktrin Zero-Physical-Write*).
5. Klik **`DPI Hex`** untuk memperlihatkan diseksi paket biner Modbus/TCP dan Function Code.
6. Klik **`[APT] Kampanye Terpadu`**: Garis vektor serangan APT merah akan dirender di atas Peta ESRI menghubungkan pangkalan lintas wilayah.
7. Klik tombol emas **`BAP-FD (.docx)`** untuk mengunduh berkas laporan forensik digital resmi siap verifikasi.

---

## 📁 Struktur Direktori Proyek

```
.
├── lakon/               # Definisi skenario fisik (Depo BBM, CCTV, Genset)
├── telemetry/           # Model matematika telemetri hidup & generator teks
├── kelir/               # Proxy Modbus/TCP, penilaian sesi, data diode cermin keadaan
├── shadows/             # Layanan umpan (Modbus Decoy, HMI Web SCADA, ESMTP Phishing)
├── engine/              # Mesin kedalaman adaptif, ATT&CK ICS, pembuat aturan nftables
├── evidence/            # Rantai-hash SHA-256, Merkle tree RFC 6962, penyimpan SQLite
├── console/             # API FastAPI, Dalang Console (HTML5/Leaflet), Telegram bot, BAP report
├── sim_attacker/        # Simulator penyerang T1-T3, harness evaluasi ilmiah
├── hosting_gateway/     # Konfigurasi reverse-proxy subdomain cPanel (index.php, .htaccess)
├── tests/               # 34 test suite pengujian modul & integrasi end-to-end
├── docs/                # Arsitektur detail, hasil evaluasi Bab 13, protokol uji buta
├── Dockerfile           # Konfigurasi container non-root aman
├── Procfile             # Konfigurasi proses cloud deployment
├── render.yaml          # Spesifikasi infrastruktur otomatis Render Cloud
├── LICENSE              # Lisensi Apache 2.0 & klausul riset pertahanan
└── run_wayang.py        # Entrypoint utama server C4ISR multi-node
```

---

## 📜 Kepatuhan Regulasi, Integritas Rahasia & Lisensi

- **Perlindungan Kredensial & Bebas Rahasia**: Repositori ini tidak memuat token, kunci API, atau kredensial sensitif dalam riwayat commit git. Variabel operasional (seperti token Telegram Bot) sepenuhnya dibaca melalui environment variable (`.env` yang diabaikan oleh `.gitignore`).
- **Etika Pertahanan Siber**: Sistem ini 100% defensif (*zero hack-back*), tidak memuat kode eksploitasi ofensif, dan seluruh manipulasi diisolasi di lingkungan virtual internal.
- **Lisensi Perangkat Lunak**: Dilisensikan di bawah [Apache License 2.0](LICENSE) dengan klausul hak guna dan riset teknologi pertahanan nasional untuk TNI Angkatan Darat dalam rangka **Kartika Cyber Hackathon 2026**.
