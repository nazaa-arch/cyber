# WAYANG: Deception Grid Adaptif untuk Pertahanan IT/OT Satuan TNI AD

[![CI/CD Pipeline](https://github.com/nazaa-arch/cyber/actions/workflows/ci.yml/badge.svg)](https://github.com/nazaa-arch/cyber/actions/workflows/ci.yml)
[![Tests Passing](https://img.shields.io/badge/tests-29%2F29%20passed-brightgreen.svg)]()
[![Zero Real Writes](https://img.shields.io/badge/physical%20safety-0%20real%20writes-blue.svg)]()
[![Detection TTFA](https://img.shields.io/badge/TTFA-1.5ms%20(median)-orange.svg)]()
[![Memory Footprint](https://img.shields.io/badge/RAM-81%20MB-purple.svg)]()
[![TNI AD Kartika Cyber](https://img.shields.io/badge/Kartika%20Cyber-Hackathon%202026-darkred.svg)]()

> **Doktrin Pertahanan**: 100% defensif. Nol dampak pada aset fisik riil. Zero hack-back. Sesuai proposal teknis: `WAYANG - Proposal Teknis Kartika Cyber Hackathon 2026.docx`.

---

## 🛡️ Ringkasan Eksekutif

**WAYANG** adalah kerangka kerja *Adaptive Deception Grid* berbasis edge yang dirancang khusus untuk melindungi infrastruktur komando, logistik, dan operasional pangkalan **TNI Angkatan Darat**.

Berbeda dengan honeypot tradisional yang pasif dan mudah di-sidik jari (fingerprinted) oleh penyerang tingkat lanjut (APT), WAYANG mengintegrasikan proxy transparan (**Kelir**), model fisika telemetri hidup (**Living Telemetry**), pengalihan sesi dinamis (**Shadow Divert**), serta transmisi telemetri searah (**Logical Data Diode State Mirror**). Semua interaksi penyerang dialihkan ke lingkungan umpan berlapis tanpa menyadari bahwa mereka telah terisolasi, sementara aset fisik riil tetap beroperasi 100% aman dan tidak tersentuh.

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
                     ┌──────────────────┐  ┌───────────────────────────────────┐
                     │    ASET ASLI     │  │         BAYANGAN (DECOY)          │
                     │  (PLC / SCADA)   │  │ - Modbus Decoy + Ladder Timing    │
                     │                  │  │ - HMI Web SCADA Decoy             │
                     │  100% Terlindungi│  │ - ESMTP Decoy & Honeytokens       │
                     └─────────┬────────┘  └─────────────────┬─────────────────┘
                               │ (Polling Cermin             │
                               │  Satu Arah)                 ▼
                               └─────────────► ┌───────────────────────────────┐
                                               │        MESIN ADAPTIF          │
                                               │ - Optimalisasi Kedalaman      │
                                               │ - Pemetaan MITRE ATT&CK ICS   │
                                               │ - Hash-Chain SHA-256          │
                                               └───────────────┬───────────────┘
                                                               │
                                                               ▼
                                               ┌───────────────────────────────┐
                                               │   SIKLUS BAYANGAN KE BENTENG  │
                                               │ - Sigma & STIX 2.1 IOC        │
                                               │ - nftables Blokir Otomatis    │
                                               │ - Dalang Console & Telegram   │
                                               │ - Berita Acara Forensik (BAP) │
                                               └───────────────────────────────┘
```

---

## 🌟 Keunggulan Utama & Fitur Strategis

### 1. Zero Physical Impact Guarantee (Jaminan Nol Kerusakan Fisik)
- Menggunakan arsitektur **Kelir Modbus Proxy** dengan mitigasi *fail-closed*.
- Trafik dari IP operator sah yang terdaftar dalam daftar putih diteruskan ke PLC fisik riil.
- Setiap paket manipulasi atau pemindaian dari entitas tak terdaftar langsung dialihkan (*Shadow Divert*) ke bayangan PLC virtual.
- Terbukti melalui pengujian benchmark: **0 perintah tulis penyerang yang mencapai aset riil**.

### 2. High-Fidelity Physics & Scan-Cycle Timing Emulation
- **Physics Fidelity**: Mensimulasikan dinamika fisik fluida (efek *water hammer* saat katup ditutup mendadak, siklus suhu diurnal tangki BBM, serta fluktuasi beban frekuensi 50 Hz pada genset).
- **PLC Scan-Cycle Emulation**: Bayangan merespons Modbus dengan penundaan berbasis siklus scan tangga PLC riil (15–25 ms fase siklus), meniadakan kemungkinan penyerang membedakan honeypot melalui *TCP kernel turnaround time*.

### 3. Tiga Skenario Lakon Satuan Militer Operasional
1. **Lakon 1: Depo BBM Satuan (`lakon/depo_bbm_satuan.yaml`)**:
   - Telemetri level tangki bahan bakar solar, katup pipa masuk/keluar, pompa transfer, dan sensor tekanan pipa dengan mitigasi transien fluida.
2. **Lakon 2: Gerbang Pangkalan & CCTV NVR (`lakon/gerbang_cctv.yaml`)**:
   - Kontrol barrier gate, status kamera perimeter, umpan kredensial administratif (`admin:admin`), serta *honeytoken* berkas konfigurasi firmware palsu.
3. **Lakon 3: Genset Listrik & ATS Pangkalan (`lakon/genset_listrik.yaml`)**:
   - Sistem transfer daya otomatis (ATS/UPS), telemetri frekuensi 50 Hz, voltase 380V 3-fasa, dan level tangki harian genset darurat.

### 4. Bayangan Sosial & Umpan Phishing (ESMTP Decoy)
- Menyediakan *fake personas* (Pejabat Logistik Satuan, Perwira Jaga).
- Honeydoc dokumen kedinasan ber-kanari (canary token embedded).
- Decoy server ESMTP (`shadows/smtp_shadow.py`) yang menangkap surat elektronik phishing penyerang tanpa meneruskannya ke jaringan internal.

### 5. Tactical Twin-Screen Console & Live Attack Playground
- **Tactical Twin-Screen**: Menampilkan perbandingan *side-by-side* secara *real-time* antara kondisi Aset Fisik Riil vs Bayangan Umpan yang sedang dimanipulasi penyerang.
- **Live Attack Playground**: Tombol simulasi serangan terintegrasi (T1 Pemindai Oportunis, T2 Manipulasi Terarah, T3 Uji Konsistensi, dan Phishing) untuk mempermudah demonstrasi langsung di hadapan dewan juri.

### 6. Rantai Bukti Hukum & Forensik Militer (BAP-FD)
- Setiap event dienkapsulasi dalam **SHA-256 Hash-Chain** yang tidak dapat diubah (*tamper-proof*).
- Menghasilkan dokumen resmi **Berita Acara Pemeriksaan Forensik Digital (BAP-FD)** format `.docx` dan `.html` lengkap dengan KOP Markas Besar / Satuan TNI AD, klasifikasi RAHASIA, dan tabel rantai hash forensik yang sah secara hukum.

---

## 📊 Hasil Uji & Benchmark Evaluasi

Pengujian otomatis dijalankan melalui modul evaluasi ilmiah (`sim_attacker/evaluate.py`) menghasilkan metrik berikut:

| Parameter Evaluasi | Target Proposal | Hasil Terukur | Status |
|---|---|---|---|
| **False Positive Rate (FPR)** | 0% pada operator sah | **0.0%** (105/105 sukses) | **TERPENUHI** |
| **Presisi & Recall Deteksi** | 100% | **1.0 (100%) / 1.0 (100%)** | **TERPENUHI** |
| **Waktu Peringatan Pertama (TTFA)** | < 3.000 ms | **1.50 ms** (median) / **2.26 ms** (p95) | **UNGGUL (sub-3ms)** |
| **Dwell Time Penyerang (Adaptif)** | Peningkatan > 25% | **+48.7%** (27.5s vs 18.5s) | **UNGGUL (+48.7%)** |
| **Manipulasi Tembus ke Aset Riil** | 0 penulisan | **0 penulisan** (5/5 sah, 0/12 penyerang) | **TERLINDUNGI PENUH** |
| **Integritas Rantai Hash** | Valid SHA-256 | **Valid (chain_ok = true)** | **TERVERIFIKASI** |
| **Penghematan Bandwidth Taktis** | > 50% | **71.7%** rasio kompresi ringkasan | **TERPENUHI** |
| **Penggunaan Memori (RAM)** | < 256 MB | **81.2 MB** total RSS | **SANGAT RINGAN** |

---

## 🚀 Panduan Memulai Cepat (Quick Start)

### Persyaratan Sistem
- Python 3.10 atau lebih baru.
- Sistem Operasi: Linux, Windows, atau macOS.
- Tanpa dependensi GPU eksternal (100% berjalan di edge / laptop taktis).

### 1. Instalasi Dependensi
```bash
git clone https://github.com/nazaa-arch/cyber.git
cd cyber/wayang
pip install -r requirements.txt
```

### 2. Menjalankan Pengujian Otomatis (29 Unit Tests)
```bash
python -m pytest tests -q -p no:warnings
```

### 3. Menjalankan Konsol Komando Dalang (Satu Perintah)
Pada Windows:
```cmd
start_demo.bat
```
Atau via terminal:
```bash
python -m demo --mode full --port 8080
```
Buka peramban di: **`http://127.0.0.1:8080`**

### 4. Opsi Deployment Kontainer (Docker / GHCR)
WAYANG telah dikemas secara otomatis melalui GitHub Actions ke GitHub Container Registry (`ghcr.io`):
```bash
# Menjalankan langsung via docker-compose
docker compose up -d

# Atau pull image rilis resmi
docker pull ghcr.io/nazaa-arch/cyber:latest
```

---

## 🎮 Panduan Demonstrasi Live Hackathon

1. Buka **Dalang Command Center** di `http://127.0.0.1:8080`.
2. Arahkan pandangan ke panel **Tactical Twin-Screen**:
   - Di sisi kiri: Status **Aset Fisik Riil** (Level BBM 78.4%, Pompa MATI, Tekanan 0.0 Bar).
   - Di sisi kanan: Status **Bayangan Decoy** yang siap menerima penyerang.
3. Pada panel **Live Attack Playground**, klik tombol:
   - `[T1] SCANNER RUN`: Simulasi pengintaian port dan register Modbus.
   - `[T2] TARGETED ATTACK`: Simulasi injeksi Modbus Write ke katup bahan bakar.
4. **Perhatikan Perbedaannya**:
   - Bayangan langsung menyerap penulisan (Level BBM di bayangan melonjak atau katup terbuka).
   - **Aset Fisik Riil tetap tenang dan tidak mengalami perubahan sedikit pun!**
   - Notifikasi intelijen taktis seketika terkirim ke bot Telegram Dalang (`@Dalangwayangbot`).
   - Tombol draf pertahanan (*nftables* / *Sigma*) siap di-approve oleh Komandan/Operator.
5. Klik **"Unduh BAP-FD (.docx)"** di header konsol untuk mencetak laporan forensik resmi berstandar militer.

---

## 📁 Struktur Direktori

```
wayang/
├── lakon/               # Definisi skenario fisik (Depo BBM, CCTV, Genset)
├── telemetry/           # Model matematika telemetri hidup & generator teks
├── kelir/               # Proxy Modbus/TCP, penilaian sesi, cermin keadaan satu arah
├── shadows/             # Layanan umpan (Modbus Decoy, HMI Web SCADA, ESMTP Phishing)
├── engine/              # Mesin kedalaman adaptif, ATT&CK ICS, pembuat aturan, persetujuan
├── evidence/            # Rantai-hash SHA-256 dan penyimpan sesi SQLite
├── console/             # API FastAPI, Dalang Console (HTML5/Leaflet), Telegram bot, BAP report
├── sim_attacker/        # Simulator penyerang T1-T3, harness evaluasi ilmiah
├── tests/               # 29 test suite pengujian modul & integrasi end-to-end
├── docs/                # Arsitektur detail, hasil evaluasi, panduan demo dewan juri
├── Dockerfile           # Konfigurasi container non-root aman
└── docker-compose.yml   # Orkestrasi multi-kontainer
```

---

## 📜 Kepatuhan Regulasi & Lisensi

- Dibuat untuk kepentingan pengujian pertahanan siber nasional (**Kartika Cyber Hackathon 2026 TNI AD**).
- Mengikuti pedoman etika siber: Tidak mengandung modul ofensif, tidak melakukan serangan balik (*zero hack-back*), dan seluruh pengujian dijalankan pada lingkungan virtual terisolasi.
- Lisensi: Hak cipta milik pengembang untuk TNI AD.
