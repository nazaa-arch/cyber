# Panduan Presentasi & Demonstrasi Langsung: Kartika Cyber Hackathon 2026

Buku saku ini disiapkan khusus agar Anda dapat membawakan demonstrasi **WAYANG** secara percaya diri, taktis, dan meyakinkan di hadapan Dewan Juri (Pusinfolahta TNI AD, Satcyber TNI, BSSN, dan Pakar Industri Siber).

---

## ⏱️ Struktur Durasi Presentasi

| Durasi | Fokus Presentasi |
|---|---|
| **Opsi A: 3 Menit** (Babak Cepat / Eliminasi) | Masalah Utama (30s) ➔ Solusi Kelir & Twin-Screen Demo (1.5m) ➔ Dampak Militer & BAP-FD (1m) |
| **Opsi B: 5 Menit** (Format Standar Final) | Latar Belakang & Doktrin (1m) ➔ Arsitektur Kelir & Fisika (1m) ➔ Live Demo 2 Skenario (2m) ➔ Siklus Benteng & Bukti Forensik (1m) |
| **Opsi C: 10 Menit** (Grand Final / Deep Dive) | Lengkap dengan Pembahasan Multi-Satuan APT, Resiliensi Radio Taktis, dan Tanya-Jawab Dewan Juri |

---

## 🎯 Skenario Live Demo 5 Menit (Langkah demi Langkah)

### Menit 00.00 – 01.00: Pembukaan & Paradigma Pertahanan
- **Ucapkan:**
  > *"Siap Komandan, Dewan Juri yang terhormat. Di era perang modern, aset Operational Technology (OT) TNI AD—mulai dari Depo BBM, Genset Radar, hingga Pangkalan Udara—menjadi target utama serangan siber sabotase. Honeypot konvensional hari ini memiliki dua kelemahan fatal: Pertama, berdiri di IP sampingan sehingga jika penyerang menyerang IP asli, PLC fisik tetap hancur. Kedua, nilai sensornya statis sehingga peretas tingkat lanjut (APT) dengan mudah menyadari jebakan tersebut dalam hitungan detik.*
  > *Kami mempersembahkan **WAYANG: Adaptive Deception Grid untuk Pertahanan IT/OT Satuan TNI AD**."*

### Menit 01.00 – 02.00: Pengenalan Arsitektur & Tactical Twin-Screen
- **Aksi Layar:** Tampilkan layar Dalang Command Center (`http://127.0.0.1:8080`).
- **Ucapkan:**
  > *"Di layar depan Anda adalah Konsol Dalang. Perhatikan panel **Tactical Twin-Screen** di bagian atas:*
  > *- Sisi Kiri adalah **ASET FISIK RIIL** (Depo BBM Kodim-03): Level solar 78.4%, pompa mati, tekanan 0.0 Bar.*
  > *- Sisi Kanan adalah **BAYANGAN UMPAN (DECOY)** yang cerminannya disinkronkan secara searah oleh gerbang **Kelir Proxy**.*
  > *Kelir bertindak inline secara fail-closed. Operator sah dari daftar putih diteruskan ke aset riil. Namun setiap entitas tak dikenal yang mencoba menguji register akan langsung diisolasi ke dalam dunia bayangan tanpa disadari."*

### Menit 02.00 – 03.30: Aksi Serangan Langsung (Live Attack Playground)
- **Langkah 1: Klik tombol `[T1] SCANNER RUN`**
  - **Ucapkan:**
    > *"Kami mensimulasikan pemindai oportunis yang mencari port Modbus 502 terbuka. Dalam waktu **1.5 milidetik (sub-3ms)**, Kelir mendeteksi pemindaian sekuensial, mengidentifikasinya sebagai Reconnaissance MITRE ATT&CK T0843, dan memicu peringatan taktis tanpa mengganggu jalur komunikasi pangkalan."*
- **Langkah 2: Klik tombol `[T2] TARGETED ATTACK`**
  - **Ucapkan:**
    > *"Sekarang penyerang APT mencoba melakukan sabotase fisik: mengirim perintah Modbus Function Code 06 untuk memaksa katup bahan bakar terbuka penuh dan memicu pompa transfer.*
    > *Perhatikan apa yang terjadi di Tactical Twin-Screen:*
    > *- Di sisi kanan (Bayangan), nilai katup terbaca TERBUKA dan pompa aktif. Penyerang merasa operasinya sukses.*
    > *- Namun lihat di sisi kiri: **ASET FISIK RIIL TETAP 100% AMAN!** Pompa asli tetap MATI, katup asli tetap tertutup rapat. Zero writes reached the physical asset."*
- **Langkah 3: Tunjukkan Notifikasi Telegram**
  - Buka Telegram / perlihatkan layar bot [@dalangwayangbot](https://t.me/dalangwayangbot). Juri bisa ikut menerima notifikasi dengan mengirim `/start` ke bot (hanya-baca).
  - **Ucapkan:**
    > *"Secara bersamaan, bot telegram `@dalangwayangbot` di genggaman Perwira Jaga Satuan langsung berbunyi membawa intelijen taktis lengkap dengan tombol persetujuan blokir."*

### Menit 03.30 – 04.30: Siklus Bayangan ke Benteng & Forensik BAP-FD
- **Aksi Layar:** Scroll ke tabel **Siklus Bayangan ke Benteng** dan **Rantai Bukti Hash**.
- **Ucapkan:**
  > *"WAYANG tidak berhenti pada pengalihan. Intelijen musuh langsung diekstraksi menjadi benteng perlindungan:*
  > *1. Menghasilkan aturan **Sigma** dan IoC **STIX 2.1** untuk disebarkan ke seluruh satuan Korem/Kodam.*
  > *2. Menyusun draf pemblokiran **nftables** seketika.*
  > *3. Seluruh jejak audit terkunci dalam **Rantai Hash SHA-256** anti-manipulasi.*
  > *4. Terhubung ke SOC satuan: alert **Suricata** langsung membuat penyerang dialihkan ke bayangan, setiap event bayangan masuk **Wazuh SIEM**, dan draf rule Suricata per penyerang siap disetujui."*
  - **Opsional (demo integrasi):** jalankan `python integrations/lab/demo_alur.py` untuk menunjukkan alur Suricata → WAYANG → Wazuh dengan PLC asli menerima 0 tulis.
- **Langkah 4: Klik tombol `Unduh BAP-FD (.docx)` di kanan atas konsol.**
  - Buka berkas Word yang terunduh.
  - **Ucapkan:**
    > *"Dan untuk komando atas serta pembuktian hukum militer, sistem kami mengenerate otomatis **Berita Acara Pemeriksaan Forensik Digital (BAP-FD)** resmi dengan format standar TNI AD lengkap dengan nomor register, klasifikasi rahasia, tabel kronologi, dan lembar pengesahan tanda tangan penyidik."*

### Menit 04.30 – 05.00: Penutup
- **Ucapkan:**
  > *"Sistem ini dirancang sangat ringan—hanya **81 MB RAM**, tanpa GPU, tahan putus link satelit hingga 71.7% kompresi, dan siap dioperasikan di garis depan. WAYANG bukan sekadar konsep, tetapi benteng pertahanan digital kedaulatan TNI Angkatan Darat. Terima kasih, siap menerima arahan dan pertanyaan."*

---

## 🛡️ Antisipasi Pertanyaan Kritis Dewan Juri & Jawaban Tuntas

### Q1: *"Apakah penempatan Kelir Proxy tidak menambah latensi jaringan yang berbahaya bagi sistem kendali industri (OT/ICS)?"*
- **Jawaban Anda:**
  > *"Siap Bapak/Ibu Juri. Kami telah mengukur latensi pada modul evaluasi resmi (`sim_attacker/evaluate.py`). Latensi p95 untuk operator sah hanya berkisar **16 milidetik**, jauh di bawah ambang batas toleransi Modbus/TCP standar industri yang mencapai 200–1000 milidetik. Kami mengimplementasikan parsing Modbus langsung di atas pure asynchronous socket (asyncio) tanpa beban middleware pihak ketiga, sehingga performa mendekati wire-speed."*

### Q2: *"Bagaimana jika penyerang mengecek konsistensi data antara Modbus dan HMI Web SCADA?"*
- **Jawaban Anda:**
  > *"Pertanyaan yang sangat tajam, Juri. Inilah alasan kami mengembangkan **Mesin Adaptif Multidimensi**. Begitu penyerang mencoba membaca register dari Modbus lalu mengecek HMI Web, Mesin Adaptif mendeteksi pola cross-protocol consistency probing (Teknik T0888). Sistem secara otomatis mengaktifkan mekanisme **Freeze Depth**: nilai sensor pada Modbus Decoy dan Web SCADA Decoy disinkronkan secara konsisten sehingga penyerang tidak menemukan kontradiksi data sedikit pun."*

### Q3: *"Bagaimana jaminan bahwa proxy ini tidak gagal dan mematikan suplai BBM pangkalan (Single Point of Failure)?"*
- **Jawaban Anda:**
  > *"Arsitektur Kelir kami memiliki modul **Fail-Closed Isolation State**:*
  > *1. Jika terjadi gangguan perangkat keras atau pemutusan daya pada node WAYANG, relay bypass pasif tingkat hardware dapat dihubungkan langsung ke jalur kabel PLC.*
  > *2. Secara perangkat lunak, sistem menerapkan daftar putih IP (IP Whitelist) berbasis kernel.*
  > *3. State Mirror hanya membaca secara searah (one-way read-only) sehingga kegagalan memori di sisi bayangan tidak pernah dapat merusak register di PLC fisik."*

### Q4: *"Apakah sistem ini membutuhkan server besar atau GPU canggih untuk AI-nya?"*
- **Jawaban Anda:**
  > *"Sama sekali tidak. Doktrin perancangan kami adalah **Edge-First Tactical Defense**. Optimasi kedalaman menggunakan discrete utility-risk optimization dengan kalkulasi mikrodetik matematis, bukan inferensi deep learning yang boros daya. Total footprint memori teruji hanya **81.2 MB RAM**. Sistem ini dapat dijalankan dengan mulus di single-board computer sekelas Raspberry Pi 4 atau laptop lapangan tahan benturan (rugged laptop) di pos terluar tanpa ketergantungan cloud."*

### Q5: *"Banyak honeypot menghasilkan jutaan log palsu (false alarms) yang melelahkan operator. Bagaimana WAYANG mengatasinya?"*
- **Jawaban Anda:**
  > *"Pada hasil benchmark evaluasi kami terhadap 105 request operator sah, **False Positive Rate (FPR) adalah 0.0%**. Sesi operator sah yang terdaftar dalam daftar putih langsung diteruskan tanpa penandaan peringatan.*
  > *Peringatan hanya dibangkitkan ketika skor anomali melampaui batas ambang ($S(s) \ge 0.5$) berdasarkan 5 variabel terbobot: ketepatan port, pola urutan fungsi, kepatuhan rentang register, pelanggaran penulisan, dan timing jitter."*
