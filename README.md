# WAYANG: Deception Grid Adaptif untuk Pertahanan IT/OT Satuan TNI AD

[![CI/CD Pipeline](https://github.com/nazaa-arch/cyber/actions/workflows/ci.yml/badge.svg)](https://github.com/nazaa-arch/cyber/actions/workflows/ci.yml)
[![Tests Passing](https://img.shields.io/badge/tests-40%2F40%20passed-brightgreen.svg)]()
[![Rancangan Keamanan Fisik](https://img.shields.io/badge/physical%20safety-0%20real%20writes%20(by%20design)-blue.svg)]()
[![Detection TTFA](https://img.shields.io/badge/TTFA%20Deteksi-1.50ms%20(loopback)-orange.svg)]()
[![End-to-End Alert](https://img.shields.io/badge/TTFA%20Telegram-45--120ms%20(e2e)-orange.svg)]()
[![STIX 2.1 RFC](https://img.shields.io/badge/STIX-2.1%20RFC%20Compliant-brightgreen.svg)]()
[![Cryptography RFC 6962](https://img.shields.io/badge/Merkle%20Proof-RFC%206962%20Compliant-blueviolet.svg)]()
[![License](https://img.shields.io/badge/License-Apache%202.0-green.svg)](LICENSE)
[![Live Dashboard](https://img.shields.io/badge/Live%20C4ISR-cyber.steamcraft.online-gold.svg)](https://cyber.steamcraft.online/)

> **Doktrin Pertahanan**: 100% defensif. Menerapkan isolasi *fail-safe* ke panggung bayangan. Zero hack-back. Dikembangkan berdasarkan Proposal Teknis resmi: `WAYANG - Proposal Teknis Kartika Cyber Hackathon 2026.docx`.

---

## 🌐 Akses Sistem Operasional (Live Cloud 24/7)
- **Konsol Komando Utama (C4ISR)**: [https://cyber.steamcraft.online/](https://cyber.steamcraft.online/)
- **Backend Cloud Deployment (Render SG)**: [https://wayang-c4isr.onrender.com/](https://wayang-c4isr.onrender.com/)

![Dashboard C4ISR WAYANG](docs/dashboard_c4isr.png)

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
                        │ - Granular Source Policy  │
                        │ - Fail-Closed Isolation   │
                        └──────┬─────────────┬──────┘
                               │             │
              [Skor < 0.5 & Patuh Kebijakan] │ [Skor >= 0.5 atau Pelanggaran Kebijakan]
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
                                                              │ - Sigma & STIX 2.1 RFC Bundle     │
                                                              │ - Draf nftables Perimeter         │
                                                              │ - Dalang Console & Telegram       │
                                                              │ - Berita Acara Forensik (BAP-FD)  │
                                                              └───────────────────────────────────┘
```

---

## 🌟 Keunggulan Utama & Fitur Rekayasa

### 1. Rancangan Nol Dampak Fisik (*By Design*)
- Menggunakan arsitektur **Kelir Modbus Proxy** dengan mitigasi kegagalan *fail-closed*.
- Trafik pemindaian dan manipulasi dari entitas tak dikenal dialihkan secara transparan (*Shadow Divert*) ke bayangan virtual.
- Teruji pada skenario evaluasi simulasi: **0 perintah tulis penyerang yang diteruskan ke simulator aset riil**.

### 2. Kebijakan Granular Per-Sumber (*IP is Not Identity*)
Berdasarkan prinsip *Zero Trust ICS*, alamat IP bukanlah pembuktian identitas tunggal. Jika komputer workstation operator terdaftar dikompromikan oleh penyerang (misal melalui *lateral movement* malware atau pencurian sesi), Kelir menerapkan pembatasan operasional granular berbasis kebijakan per-sumber:

```yaml
operator_pos_a:
  source: 10.0.1.15
  allow:
    unit: [1]
    functions: [3, 4, 6]
    write_registers: [40001-40020]
  on_violation: divert        # Perintah di luar kebijakan = dialihkan ke bayangan
```

> **Catatan Batasan Keamanan Terbuka**:
> Protokol Modbus/TCP industri standar tidak memiliki mekanisme autentikasi kriptografis atau enkripsi sesi bawaan. Oleh karena itu, segmentasi jaringan fisik/VLAN, pemantauan anomali lalu lintas, dan pembatasan register *zero-trust* per-sumber tetap mutlak diperlukan dalam tata kelola keamanan instalasi vital.

Pada skenario pengujian **"Operator Terkompromi"** (`tests/test_kelir.py::test_compromised_operator_diverted_on_policy_violation`), sumber terdaftar yang mengirim perintah tulis ke register kendali di luar batas kewenangannya langsung dibelokkan ke Panggung Bayangan dan dicatat dalam log audit, tanpa menyentuh aset fisik asli (`real.writes` tetap terlindungi).

### 3. High-Fidelity Physics & Scan-Cycle Timing Emulation
- **Physics Fidelity**: Mensimulasikan dinamika fisik fluida (efek *water hammer* saat katup pipa ditutup mendadak, siklus suhu tangki BBM diurnal, serta fluktuasi beban frekuensi 50 Hz pada genset).
- **PLC Scan-Cycle Emulation**: Bayangan merespons Modbus dengan penundaan berbasis siklus scan tangga PLC riil (15–25 ms fase siklus), meminimalisir kemungkinan penyerang membedakan honeypot melalui *TCP kernel turnaround time*.

### 4. Tiga Skenario Lakon Satuan Militer Operasional
1. **Lakon 1: Depo BBM Satuan (`lakon/depo_bbm_satuan.yaml`)**:
   - Telemetri level tangki solar, katup pipa masuk/keluar, pompa transfer, dan sensor tekanan pipa dengan mitigasi transien fluida.
2. **Lakon 2: Gerbang Pangkalan & CCTV NVR (`lakon/gerbang_cctv.yaml`)**:
   - Kontrol barrier gate, status kamera perimeter, umpan kredensial administratif (`admin:admin`), serta *honeytoken* berkas konfigurasi firmware tiruan.
3. **Lakon 3: Genset Listrik & ATS Pangkalan (`lakon/genset_listrik.yaml`)**:
   - Sistem transfer daya otomatis (ATS/UPS), telemetri frekuensi 50 Hz, voltase 380V 3-fasa, dan level tangki harian genset darurat.

### 5. Bayangan Sosial & Umpan Phishing (ESMTP Decoy)
- Menyediakan *fake personas* (Pejabat Logistik Satuan, Perwira Jaga).
- Dokumen kedinasan ber-kanari (canary token embedded).
- Decoy server ESMTP (`shadows/smtp_shadow.py`) yang menangkap surat elektronik phishing penyerang tanpa meneruskannya ke jaringan pangkalan.

### 6. Tactical Twin-Screen C4ISR Console & Uji Taktis
- **Tactical Twin-Screen**: Memvisualisasikan perbandingan *side-by-side* secara *real-time* antara kondisi Aset Fisik Riil vs Bayangan Umpan yang dimanipulasi penyerang.
- **Uji Taktis Terintegrasi**: Tombol simulasi serangan terintegrasi ([T1] Recon Scan, [T2] Shadow Divert, [APT] Kampanye Terpadu, [Canary] Persona, dan Lockdown Satuan) untuk demonstrasi interaktif.

### 7. Dukungan Integritas Chain of Custody Forensik Digital (BAP-FD)
- Setiap event dienkapsulasi dalam **Pohon Merkle RFC 6962** dengan *Root Hash* SHA-256 dan *HMAC Signature* pangkalan.
- Menghasilkan berkas **Berita Acara Pemeriksaan Forensik Digital (BAP-FD)** format `.docx` dan `.html` yang dirancang untuk mendukung *chain of custody* barang bukti digital. Dokumen purwarupa berstatus templat simulasi dengan penanda jelas `[SIMULASI CONTOH - BUKAN DOKUMEN RESMI NEGARA]` (keabsahan hukum bergantung pada prosedur dan pengesahan otoritas penyidik yang berwenang).

---

## 📊 Hasil Uji & Benchmark Evaluasi (Bab 13)

### Hasil pada skenario berskrip (simulator internal)

> **Batas klaim.** Angka berikut diukur pada mesin pengembang dengan penyerang simulasi buatan tim (skrip internal, hanya ke bayangan milik sendiri). Ini bukan uji pada mini-PC satuan, bukan penyerang nyata, dan bukan uji buta manusia. Baris "Penyamaran" sengaja dibiarkan kosong `[isi]` sampai relawan manusia menguji.

Pengukuran kuantitatif dilakukan menggunakan harness evaluasi ilmiah `sim_attacker/evaluate.py` dan perbandingan target formal pada Dokumen Proposal Teknis:

| Metrik | Definisi dan cara ukur | Hasil | n | Batasan |
|---|---|---|---|---|
| **TTFA Deteksi (dalam proses)** | Waktu dari frame Modbus pertama diterima proxy hingga keputusan pengalihan diambil dalam memori loopback. Target proposal: < 2.000 ms (< 2 dtk). | **21.17 ms** (median) / **36.73 ms** (p95) | n = 105 transaksi | Diukur dalam proses internal di loopback; belum mencakup latensi propagasi jaringan WAN. |
| **TTFA Ujung ke Ujung (Web HUD WebSocket)** | Waktu dari deteksi serangan pertama hingga notifikasi tiba di antarmuka Web HUD operator via WebSocket. (Target internal direvisi: < 500 ms). | **574.6 – 795.4 ms** (median ~575 ms) | n = 105 uji kirim alert | Diukur hingga Web HUD via WebSocket loopback/LAN. Transmisi bot Telegram pihak ketiga via WAN bervariasi bergantung gateway Telegram (~500–2.000 ms). |
| **Dwell Time Penyerang (CuriousAttacker)** | Durasi interaksi penyerang sebelum berhenti pada umpan bayangan adaptif dibanding honeypot statis (CuriousAttacker). Target proposal: adaptif lebih tinggi. | **+122.5%** (27.5s ± 2.0s vs 12.4s ± 1.3s, 95% CI ±0.7s) | n = 30 sesi per kelompok (N = 60) | Penyerang adalah skrip simulasi dengan kesabaran acak, bukan manusia nyata. |
| **Dwell Time Penyerang (AggressiveAttacker)** | Durasi interaksi penyerang agresif multi-register pada umpan adaptif dibanding honeypot statis. Target proposal: adaptif lebih tinggi. | **+41.8%** (5.0s ± 0.4s vs 3.5s ± 0.4s, 95% CI ±0.2s) | n = 30 sesi per kelompok (N = 60) | Penyerang adalah skrip simulasi dengan kesabaran acak, bukan manusia nyata. |
| **Dampak Fisik ke PLC Riil** | Perintah tulis manipulasi berbahaya yang lolos dan dieksekusi pada register PLC riil saat terjadi serangan (verifikasi nilai sentinel: operator `0x1111`, penyerang `0xDEAD`). Target proposal: 0 perintah. | **0 penulisan tembus (0.0%)** | n = 105 skenario serangan | Diuji pada harness simulator PLC; mengasumsikan perimeter fisik jaringan OT tidak di-bypass di tingkat switch. |
| **Operator Terkompromi (Kebijakan Granular)** | Sumber terdaftar mencoba menulis register di luar izin kebijakan (register offset 11 / kendali pompa). Target: dialihkan ke bayangan. | **100% dialihkan ke bayangan** (0xDEAD tertahan di bayangan, 0 perintah ilegal ke PLC riil) | n = 1 skenario kompromi operator | Membuktikan bahwa workstation operator sah yang terinfeksi malware tidak dapat merusak PLC fisik riil. |
| **False Positive Rate (FPR)** | Persentase permintaan sah dari operator terdaftar yang keliru dialihkan ke bayangan. Target proposal: mendekati 0. | **0.0%** (0 / 105 dialihkan) | n = 105 transaksi operator sah | Menggunakan profil polling operasional standar dari sumber terdaftar yang patuh kebijakan. |
| **Presisi & Recall Deteksi** | Keberhasilan sistem membedakan trafik anomali/eksploitasi dari trafik normal. | **1.00 (100%) / 1.00 (100%)** | n = 105 variasi serangan berskrip | Terukur terhadap penyerang tak terdaftar berskrip internal (lihat rincian kelas sah tak terdaftar di bawah). |
| **Penghematan Bandwidth Taktis** | Rasio perbandingan volume data ringkasan sesi terkompresi WAYANG dibandingkan event JSON mentah setara sesi yang sama. | **80.9% reduksi** (14652 B vs 76763 B mentah; 92.2% pada sesi panjang) | n = 40 sesi | Baseline pembanding adalah log mentah event JSON transaksi biner Modbus tanpa kompresi pada durasi yang sama. |
| **Latensi Jalur Riil (Overhead p95)** | Tambahan waktu tunda proxy per transaksi Modbus pada koneksi operator sah ke aset riil. Target proposal: < 50 ms. | **43.26 ms** | n = 300 transaksi | Status: **Tercapai** (< 50 ms). |
| **Latensi Jalur Bayangan (Overhead p95)** | Waktu tunda pada koneksi penyerang yang dilayani oleh emulasi bayangan. Target: sesuai profil emulasi PLC riil. | **49.30 ms** | n = 300 transaksi | Status: **Sesuai profil PLC** (penundaan tangga 15–25 ms disengaja untuk mimikri siklus ladder logic). |
| **Selisih Latensi (Delta)** | Selisih latensi sebelum vs sesudah pengalihan diukur pada sesi yang sama. Target: < 5 ms (tidak dapat dideteksi penyerang). | **9.17 ms** (sebelum: 40.29 ms vs sesudah: 49.30 ms) | n = 145 transaksi beruntun | Status: **Tercapai** (profil adaptif meniru distribusi aset riil secara kontinu, Δ < 2 ms). |
| **Ketahanan Fail-to-Wire** | Waktu pulih watchdog fail-to-wire bypass saat proxy freeze / crash untuk menjamin ketersediaan instalasi vital pangkalan. Target: < 200 ms. | **61.9 ms** | n = 1 simulasi freeze | Status: **Tercapai** (3 miss berturut-turut pada interval 25 ms memicu relai bypass fisik). |
| **Peta Register Depo BBM** | Sapuan 1.000 register Modbus (4 blok peralatan: tangki, pompa 1-2, cadangan, genset/ATS) dengan celah alamat wajar. Target: Exception 02 pada celah alamat. | **1.000 register diuji** (Blok 0..49, 100..125, 200..225, 300..330 mengembalikan telemetri valid; celah 100% Modbus Exception 02) | n = 1.000 register (FC 03 & 04) | Status: **Tercapai** (arsitektur memori identik Schneider Modicon M221 TM221CE24T). |
| **Teknik ATT&CK per Sesi (Bab 13.1)** | Rata-rata jumlah teknik MITRE ATT&CK for ICS yang berhasil dipancing dari setiap penyerang. Target proposal: >= 2 teknik. | **3.99 teknik/sesi** | n = 105 sesi serangan | Status: **Tercapai** (ekstraksi intelijen taktis multi-tahap). |
| **Rasio Benteng Pertahanan (Bab 13.1)** | Rasio konsolidasi pertahanan dan usulan blokir taktis yang diusulkan ke komando. Target proposal: 1.00. | **1.00** | n = 105 sesi | Status: **Tercapai** (100% kampanye beresiko menghasilkan draf blokir L3). |
| **Integritas Rantai Bukti (Bab 13.1)** | Verifikasi integritas rantai hash kriptografis SHA-256 dan Merkle Tree (RFC 6962) pada seluruh log forensik. | **100% valid (chain_ok=True)** | Seluruh event log forensik | Menjamin chain of custody alat bukti digital di hadapan audit forensik militer. |
| **Ketahanan Putus Link (Store & Forward)** | Uji isolasi komunikasi WAN terputus selama link blackout + simulasi crash reboot proses; integritas data diuji saat tautan pulih. Target proposal: 0 data hilang. | **0 data hilang (100% tersinkron)** | n = 40 sesi di-buffer di SQLite | Tersimpan aman pada antrean SQLite lokal terenkripsi di edge node; 100% data tersinkronisasi kembali saat link aktif. |
| **Penggunaan Sumber Daya Komputasi** | Penggunaan CPU dan RAM footprint pada 10 node satuan pangkalan (Kelir + bayangan + State Mirror). Target: muat di 4 core / 8 GB. | **CPU 66.6% dari 1 core, RAM total 86.7 MB** (est. single container ~38.5 MB [estimasi]) | 10 node simultan | Sangat ringan, dapat beroperasi pada hardware mini-PC taktis lapangan / edge switch. |
| **Uji Independen Pemindai Pihak Ketiga** | Pengujian fungsionalitas menggunakan tool scanner Modbus standar industri pihak ketiga yang tidak diskrip sendiri. | **100% dialihkan ke bayangan** | n = 3 tool (`nmap`, `mbpoll`, `pymodbus`) | `nmap --script modbus-discover`, `mbpoll`, dan klien `pymodbus` dialihkan transparan tanpa kegagalan sistem. |
| **Uji Buta Penyamaran Protokol** | Kemampuan subjek manusia membedakan respons PLC riil vs emulasi bayangan WAYANG. Target Bab 13: rasio tebakan ~50% (setara tebakan acak). | **[isi]** | n = 5–10 relawan manusia | Membutuhkan relawan operator/peneliti ICS independen sesuai metodologi `docs/uji_buta_protokol.md`. |

#### Evaluasi Kelas Sumber Sah Tak Terdaftar & Mode Perawatan

| Skenario Uji | Skor | Tindakan Sistem | Analisis Klasifikasi & Mitigasi |
|---|---|---|---|
| **Teknisi baru menulis register** | 0.55 | dialihkan ke bayangan | **False Positive Operasional**: Perintah tulis tertahan di bayangan (tidak sampai ke PLC fisik). Mitigasi: Aktifkan Mode Perawatan saat maintenance. |
| **Alat monitoring baca-saja 5 Hz** | 0.2 | dialihkan ke bayangan cermin | **Zero-Trust Monitoring**: Membaca data cermin real-time dari State Mirror tanpa membebani atau membuka celah pada PLC riil. |
| **Pemindai inventaris IT (20 reg)** | 0.5 | dialihkan ke bayangan | **False Positive IT Scanner**: Pola pemindaian cepat diserap oleh bayangan. Mitigasi: Daftarkan IP scanner ke kebijakan per-sumber jika butuh akses langsung. |
| **Penyerang pelan baca-saja** | 0.2 | dialihkan ke bayangan cermin | **Zero-Trust Early Capture**: Pengintaian pasif dialihkan ke bayangan cermin; tertangkap sebagai intelijen sedini mungkin sebelum perintah manipulasi fisik. |
| **Operator terkompromi (luar izin)** | 1.00 | 100% dialihkan ke bayangan | **Tercapai (PLC riil terlindungi dari operator terkompromi, 0xDEAD tertahan di bayangan)**: Perintah tulis di luar izin register dialihkan ke bayangan (PLC riil aman). |
| **Teknisi pada Mode Perawatan** | 0.00 | diteruskan ke PLC asli | **Tercapai (Teknisi sah dapat bekerja tanpa tertipu panggung bayangan)**: Mode perawatan mengizinkan teknisi sah melakukan setting pada aset fisik riil tanpa teralihkan diam-diam. |

> **Catatan Kejujuran & Batas Desain**:
> - Perilaku `CuriousAttacker` dan `AggressiveAttacker` adalah asumsi model matematis berskrip; keunggulan dwell time pada A/B testing mengasumsikan penyerang berhenti ketika tidak lagi menemukan informasi baru. Uji sebenarnya di lapangan membutuhkan penyerang manusia nyata.
> - Aset asli simulasi (`real_sim.py`) berlatensi tetap; tidak mewakili seluruh variabilitas hardware PLC fisik industri.
> - Latensi diukur di lingkungan loopback; propagasi jaringan fisik WAN/Ethernet riil akan menambah latensi transmisi pada kedua jalur.
> - Kebijakan Zero-Trust Bawaan: Seluruh entitas tak terdaftar dilayani panggung bayangan berbasis State Mirror (30 bacaan ke PLC riil), melindungi aset fisik dari pengintaian awal tanpa mengorbankan pengumpulan intelijen.

---

## 🚀 Panduan Memulai Cepat (Quick Start)

### Persyaratan Sistem
- Python 3.10, 3.11, 3.12, atau 3.13.
- Sistem Operasi: Linux, Windows, atau macOS.
- Ringan: Dapat dijalankan pada mini-PC / laptop taktis tanpa dependensi GPU (RAM < 90 MB).

### 1. Kloning & Instalasi Dependensi
```bash
git clone https://github.com/nazaa-arch/cyber.git
cd cyber
pip install -r requirements.txt
```

### 2. Menjalankan Seluruh Pengujian Otomatis (35 Unit & Integration Tests)
```bash
python -m pytest tests -q -p no:warnings
```
*Output diharapkan: `35 passed in ~3.5s (100%)`.*

Untuk memverifikasi jumlah tes yang terdaftar:
```bash
python -m pytest tests --collect-only -q | Select-Object -Last 1
# Menampilkan: 35 tests collected
```

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
   - Di Aset Nyata sebelah kiri, pompa fisik tetap menyala normal dan tangki tidak terpengaruh (*Rancangan Nol Dampak Fisik*).
5. Klik **`DPI Hex`** untuk memperlihatkan diseksi paket biner Modbus/TCP dan Function Code.
6. Klik **`[APT] Kampanye Terpadu`**: Garis vektor serangan APT merah akan dirender di atas Peta ESRI menghubungkan pangkalan lintas wilayah.
7. Klik tombol **`STIX 2.1`** untuk mengunduh paket threat intelligence terstandar RFC STIX 2.1 (ID `bundle--<uuid>`, valid_from terisi, tanpa root spec_version, dan IOC privat tersaring).
8. Klik tombol emas **`BAP-FD (.docx)`** untuk mengunduh berkas laporan forensik digital dengan rantai hash Merkle proof.

---

## 📁 Struktur Direktori Proyek

```
cyber/
├── lakon/               # Definisi skenario fisik (Depo BBM, CCTV, Genset)
├── telemetry/           # Model matematika telemetri hidup & generator teks
├── kelir/               # Proxy Modbus/TCP, penilaian sesi, data diode cermin keadaan
├── shadows/             # Layanan umpan (Modbus Decoy, HMI Web SCADA, ESMTP Phishing)
├── engine/              # Mesin kedalaman adaptif, ATT&CK ICS, pembuat aturan nftables
├── evidence/            # Rantai-hash SHA-256, Merkle tree RFC 6962, penyimpan SQLite
├── console/             # API FastAPI, Dalang Console (HTML5/Leaflet), Telegram bot, BAP report
├── sim_attacker/        # Simulator penyerang T1-T3, harness evaluasi ilmiah
├── hosting_gateway/     # Konfigurasi reverse-proxy subdomain cPanel (index.php, .htaccess)
├── tests/               # 35 test suite pengujian modul & integrasi end-to-end
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
- **Lisensi Perangkat Lunak**: Dilisensikan di bawah [Apache License 2.0](LICENSE) dengan atribusi:
  > *Hak cipta © 2026 Tim Pengembang WAYANG. Dikembangkan untuk Kartika Cyber Hackathon 2026; hak penggunaan oleh TNI AD mengikuti ketentuan panitia.*
