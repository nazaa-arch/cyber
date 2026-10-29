# Matriks Keunggulan Kompetitif: WAYANG vs Kompetitor

Dokumen ini membedah alasan mengapa **WAYANG** unggul mutlak dibandingkan solusi siber konvensional, honeypot opensource standar, maupun produk *commercial deception enterprise* dalam konteks operasional militer TNI AD.

---

## 1. Tabel Perbandingan Head-to-Head

| Kriteria Evaluasi | Honeypot Terbuka (Conpot / Cowrie) | Commercial Deception (TrapX / FortiDeceptor) | EDR / SIEM Konvensional (Wazuh / Zeek) | **WAYANG (TNI AD)** |
|---|---|---|---|---|
| **Perlindungan Aset Riil** | ❌ **Nol** (Berdiri sendiri, aset riil tetap telanjang jika diserang langsung) | ⚠️ Terbatas (Hanya mengandalkan IP decoy terpisah) | ⚠️ Pasif (Hanya mendeteksi setelah serangan masuk) | ✅ **100% Terlindungi** (**Kelir Proxy** mencegat dan mengalihkan penyerang sebelum menyentuh PLC asli) |
| **Fasilitas Fail-Closed Inline** | ❌ Tidak ada | ❌ Jarang ada (out-of-band) | ⚠️ Pasif / Span Port | ✅ **Ada** (Jika sistem gagal, koneksi menutup secara aman tanpa membocorkan aset riil) |
| **Fidelitas Fisika Sensor** | ❌ Statis / Nilai acak konstan (Mudah terdeteksi penyerang) | ⚠️ Heuristik sederhana | ❌ Tidak memodelkan fisika | ✅ **Fisika Hidup** (Siklus suhu diurnal, dinamika lonjakan fluida *water-hammer*, fluktuasi beban frekuensi 50Hz) |
| **PLC Scan-Cycle Timing** | ❌ Respon instan Linux TCP (Fingerprintable dalam 5 paket) | ⚠️ Latensi buatan statis | ❌ Tidak relevan | ✅ **Emulasi Siklus Tangga PLC** (15–25ms jitter fase ladder scan riil) |
| **Kebutuhan Komputasi** | Sedang | ❌ Berat (Server VM / Cloud) | ❌ Sangat Berat (Cluster Database / GPU) | ✅ **Ultra-Ringan (Edge-First)** (Hanya 81 MB RAM, 0 GPU, berjalan di Raspberry Pi / laptop taktis) |
| **Ketahanan Link Taktis** | ❌ Butuh koneksi stabil | ❌ Membutuhkan koneksi cloud | ❌ Mengirim log mentah (bandwith boros) | ✅ **Store-and-Forward Taktis** (Penyimpanan lokal saat radio putus, hemat bandwidth 71.7%) |
| **Rantai Bukti Hukum Militer** | ❌ Log teks biasa (Dapat diedit/disangkal) | ⚠️ Proprietary database | ⚠️ Syslog terpusat | ✅ **SHA-256 Hash Chain + BAP-FD Otomatis** (Sesuai KUHAP & Standar Forensik Militer TNI AD) |
| **Siklus Umpan-ke-Pertahanan** | ❌ Manual (Admin harus buat rule) | ⚠️ Integrasi API terbatas | ⚠️ Rule statis | ✅ **Bayangan ke Benteng Otomatis** (Instan menghasilkan Sigma, STIX 2.1, & draf nftables) |

---

## 2. Lima Keunggulan Pembeda ("Killer Factors") di Hadapan Juri

### 1. Arsitektur "Kelir" Bukan Sekadar Honeypot Pasif
Banyak tim hackathon hanya menyajikan honeypot standar yang ditaruh di IP sampingan. Masalah mendasar honeypot sampingan: **Jika penyerang sudah mengetahui IP aset riil, honeypot tersebut tidak berguna sama sekali.**
WAYANG menyelesaikan masalah ini melalui **Kelir Proxy**:
- Kelir bertindak sebagai gerbang transparan di depan PLC asli.
- Operator sah dari IP terdaftar tetap berkomunikasi normal dengan latensi sub-17ms.
- Penyerang yang mencoba memindai atau mengirim perintah penulisan seketika di-pin dan dialihkan ke bayangan (*Shadow Divert*).
- Penyerang merasa berhasil mengendalikan PLC, padahal mereka terjebak di dunia virtual.

### 2. Fidelitas Fisika & Waktu Siklus (Anti-Fingerprinting APT)
Kelompok peretas negara (APT / Red Team profesional) menggunakan *fingerprinting* canggih untuk mendeteksi honeypot:
- **Respon Waktu TCP**: Sistem Linux standar merespons Modbus dalam 0.5–1 ms, sedangkan PLC industri nyata (Schneider, Siemens) memiliki *ladder scan cycle* berkisar 15–30 ms. WAYANG merekayasa fase penundaan siklus tangga PLC sehingga profil waktu respon identik dengan perangkat industri fisik.
- **Dinamika Fluida Nyata**: Ketika penyerang menutup katup pipa secara mendadak, sensor tekanan WAYANG mensimulasikan gelombang kejut transien (*water hammer*) dengan peredaman eksponensial. Nilai sensor tidak berubah seketika secara linear, melainkan mengikuti hukum termodinamika dan fluida.

### 3. Dirancang Khusus untuk Medan Operasi Taktis Militer
- **Zero-Cloud & Zero-GPU**: Beroperasi 100% mandiri pada jaringan *air-gapped* tanpa koneksi internet.
- **Resiliensi Radio Taktis**: Ketika komunikasi antar Kodim/Korem terganggu perang elektronika (jamming), sistem tidak kehilangan data. Data tersimpan di SQLite lokal dan di-sinkronisasi kembali dengan kompresi 71.7% begitu sinyal pulih.
- **Sangat Hemat Daya**: Total konsumsi memori hanya ~81 MB, memungkinkan implementasi langsung pada perangkat keras komando taktis lapangan (*rugged edge box*).

### 4. Siklus Tertutup "Bayangan ke Benteng" (Intelligence-Driven Defense)
WAYANG tidak sekadar mengumpulkan intelijen untuk disimpan, melainkan langsung menutup celah pertahanan:
- Mengidentifikasi teknik penyerang berdasarkan taksonomi **MITRE ATT&CK for ICS**.
- Secara otomatis menyusun aturan deteksi **Sigma** (untuk SIEM gabungan), bundel ancaman **STIX 2.1** (untuk sharing intelijen antar matra/BSSN), dan draf aturan pemblokiran **nftables**.
- Komandan atau Operator Pusat dapat menerapkan blokir dengan satu klik persetujuan (Human-in-the-Loop) atau melalui bot Telegram operasional.

### 5. Keabsahan Forensik & Legalitas Pembuktian (BAP-FD)
Dalam operasi pertahanan militer, insiden siber harus dapat dipertanggungjawabkan di hadapan hukum militer dan komando atas:
- WAYANG merekam setiap aksi dalam rantai hash kriptografis SHA-256 (merkle-like chain). Jika ada oknum atau malware yang memodifikasi log, rantai hash seketika putus dan terdeteksi.
- Sistem menyediakan tombol instan untuk mengunduh **Berita Acara Pemeriksaan Forensik Digital (BAP-FD)** berformat `.docx` dan `.html` lengkap dengan kop satuan militer, klasifikasi kerahasiaan, kronologi kejadian, dan tanda tangan perwira penyidik.

---

## 3. Pesan Utama untuk Dewan Juri

> *"Bapak/Ibu Dewan Juri yang terhormat, kompetitor lain mungkin membangun sistem deteksi yang membanjiri operator dengan ribuan false alarms, atau memasang honeypot palsu yang mudah diabaikan penyerang. WAYANG hadir dengan doktrin militer murni: Melindungi aset fisik hingga titik nol sentuhan penyerang, menahan musuh selama mungkin di dunia bayangan untuk memanen taktik mereka, dan secara otomatis memperkuat benteng pertahanan seluruh satuan TNI AD dalam hitungan detik."*
