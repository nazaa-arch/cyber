# Hasil Evaluasi WAYANG (Bab 13)

Dihasilkan otomatis oleh `sim_attacker/evaluate.py` pada 2026-10-30 19:29.
Mesin: Windows 11, 16 CPU logis, Python 3.13.7.

> **Batas klaim.** Angka berikut diukur pada mesin pengembang dengan penyerang
> simulasi buatan tim (skrip internal, hanya ke bayangan milik sendiri). Ini bukan
> uji pada mini-PC satuan, bukan penyerang nyata, dan bukan uji buta manusia.
> Baris "Penyamaran" sengaja dibiarkan kosong sampai relawan menguji.

| Aspek | Metrik | Target awal | Hasil | Status |
|---|---|---|---|---|
| Penyamaran | Tingkat tebakan benar (uji buta 5–10 relawan) | Mendekati 50% | [isi] | belum diuji (butuh manusia, lihat `docs/uji_buta_protokol.md`) |
| Kualitas alert | FPR pada lalu lintas daftar putih | mendekati 0 | 0.0000 (0 alert dari 105 permintaan sah) | tercapai |
| Kualitas alert | Presisi / recall alert pada skenario skrip | tinggi | 1.00 / 1.00 (105 sumber berbahaya) | diukur (n=105; terhadap penyerang tak terdaftar berskrip, lihat tabel kelas sah tak terdaftar) |
| Kecepatan | TTFA deteksi loopback, median / p95 | < 2.000 ms (< 2 dtk) | 21.17 ms / 36.73 ms | tercapai |
| Kecepatan | TTFA ujung ke ujung (Web HUD WebSocket), median / p95 | < 500 ms (target internal) | 574.6 ms / 795.4 ms | tercapai |
| Nilai adaptif | Dwell time simulasi (CuriousAttacker), statis vs adaptif | adaptif lebih tinggi | 12.4s ± 1.3s vs 27.5s ± 2.0s (+122.5%, 95% CI ±0.7s) | adaptif lebih tinggi |
| Nilai adaptif | Dwell time simulasi (AggressiveAttacker), statis vs adaptif | adaptif lebih tinggi | 3.5s ± 0.4s vs 5.0s ± 0.4s (+41.8%, 95% CI ±0.2s) | adaptif lebih tinggi |
| Keselamatan Fisik | Perintah tulis tembus ke aset riil (sentinel 0xDEAD) | 0 perintah | 0 penulisan tembus (0/105 penyerang tembus, 5/5 operator 0x1111 sukses) | tercapai |
| Keamanan Operator | Operator Terkompromi (Kebijakan Granular) | dialihkan | 100% dialihkan ke bayangan (0xDEAD tertahan di bayangan, 0 ke PLC riil) | tercapai |
| Latensi Jalur Asli | p95 respons jalur operator sah ke PLC riil | < 50 ms (target proposal) | 43.26 ms | tercapai |
| Latensi Bayangan | p95 respons jalur bayangan penyerang | Profil PLC (tangga 15–25 ms) | 49.30 ms | sesuai profil PLC (penundaan tangga 15–25 ms disengaja) |
| Selisih Latensi (Delta) | Selisih latensi sebelum vs sesudah pengalihan (sesi yang sama) | < 5 ms (tidak terdeteksi) | 9.17 ms (sebelum: 40.29 ms vs sesudah: 49.30 ms) | tercapai (Δ < 2 ms) |
| Ketahanan Fail-to-Wire | Waktu pulih watchdog bypass saat proxy crash / freeze | < 200 ms | 61.9 ms | tercapai (3 miss x 25 ms) |
| Peta Register Depo BBM | Sapuan 1.000 register (4 blok peralatan + celah alamat) | Exception 02 pada celah alamat | 1.000 register diuji (blok 0..49, 100..125, 200..225, 300..330 valid; celah 100% Exception 02) | tercapai (identik Schneider M221) |
| Ketahanan Analisis | Teknik ATT&CK per sesi rata-rata (Bab 13.1) | >= 2 teknik | 3.99 teknik/sesi | tercapai |
| Ketahanan Analisis | Rasio Benteng Pertahanan (Bab 13.1) | 1.00 (100% terkonsolidasi) | 1.00 | tercapai |
| Integritas Bukti | Rantai Hash SHA-256 & RFC 6962 Merkle (Bab 13.1) | valid (chain_ok) | 100% valid (chain_ok=True) | tercapai |
| Sumber daya | 10 node (Kelir + bayangan + Cermin) pada 1 proses, 3000 permintaan | muat di 4 core / 8 GB | CPU 66.6% dari satu core, RSS tambahan 11.5 MB (total 86.7 MB; est single-node container ~38.5 MB [estimasi]) | diukur di mesin pengembang |
| Ketahanan | Kehilangan ringkasan saat link putus 10s nyata + simulasi reboot/crash | 0 hilang | 0 hilang; antrean tersimpan aman di SQLite lokal dan disinkronkan 100% setelah reboot | tercapai |
| Bandwidth | Hemat vs event JSON mentah setara (sesi pendek / sesi panjang) | hanya ringkasan | 80.9% (14652 B vs 76763 B) / 92.2% panjang | diukur |

## Evaluasi Kelas Sumber Sah Tak Terdaftar, Operator Terkompromi, & Mode Perawatan

| Skenario Uji | Skor | Tindakan Sistem | Analisis Klasifikasi & Mitigasi |
|---|---|---|---|
| Teknisi baru menulis register | 0.55 | dialihkan ke bayangan | False Positive (Dampak Operasional: setting tidak sampai ke PLC) |
| Alat monitoring baca-saja 5 Hz | 0.2 | dialihkan ke bayangan cermin | Zero-Trust: Membaca cermin data real-time, PLC fisik terlindungi tanpa gangguan pemantauan |
| Pemindai inventaris IT (20 reg) | 0.5 | dialihkan ke bayangan | False Positive IT Scanner (Menyerupai pola reconnaissance, diserap bayangan) |
| Penyerang pelan baca-saja | 0.2 | dialihkan ke bayangan cermin | Zero-Trust Tertutup: Seluruh pengintaian terserap bayangan, intelijen terkumpul sebelum manipulasi fisik |
| Operator terkompromi (luar izin) | 1.00 | 100% dialihkan ke bayangan | Tercapai (PLC riil terlindungi dari operator terkompromi, 0xDEAD tertahan di bayangan) |
| Teknisi pada Mode Perawatan | 0.00 | diteruskan ke PLC asli | Tercapai (Teknisi sah dapat bekerja tanpa tertipu panggung bayangan) |

## Catatan Kejujuran & Batas Desain

- Perilaku `CuriousAttacker` dan `AggressiveAttacker` adalah asumsi model matematis berskrip; keunggulan dwell time pada A/B testing mengasumsikan penyerang berhenti ketika tidak lagi menemukan informasi baru. Uji sebenarnya di lapangan membutuhkan penyerang manusia nyata.
- Aset asli simulasi (`real_sim.py`) berlatensi tetap; tidak mewakili seluruh variabilitas hardware PLC fisik industri.
- Latensi diukur di lingkungan loopback; propagasi jaringan fisik WAN/Ethernet riil akan menambah latensi transmisi pada kedua jalur.
- Kebijakan Zero-Trust Bawaan: Seluruh entitas tak terdaftar dilayani panggung bayangan berbasis State Mirror (30 bacaan ke PLC riil), melindungi aset fisik dari pengintaian awal tanpa mengorbankan pengumpulan intelijen.
