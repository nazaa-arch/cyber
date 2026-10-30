# Hasil Evaluasi WAYANG (Bab 13)

Dihasilkan otomatis oleh `sim_attacker/evaluate.py` pada 2026-10-30 13:21.
Mesin: Windows 11, 16 CPU logis, Python 3.13.7.

> **Batas klaim.** Angka berikut diukur pada mesin pengembang dengan penyerang
> simulasi buatan tim (skrip internal, hanya ke bayangan milik sendiri). Ini bukan
> uji pada mini-PC satuan, bukan penyerang nyata, dan bukan uji buta manusia.
> Baris "Penyamaran" sengaja dibiarkan kosong sampai relawan menguji.

| Aspek | Metrik | Target awal | Hasil | Status |
|---|---|---|---|---|
| Penyamaran | Tingkat tebakan benar (uji buta 5–10 relawan) | Mendekati 50% | [isi] | belum diuji (butuh manusia, lihat `docs/uji_buta_protokol.md`) |
| Kualitas alert | FPR pada lalu lintas daftar putih | mendekati 0 | 0.0000 (0 alert dari 105 permintaan sah) | tercapai |
| Kualitas alert | Presisi / recall alert pada skenario skrip | tinggi | 1.00 / 1.00 (105 sumber berbahaya) | diukur (n=105) |
| Kecepatan | TTFA deteksi loopback, median / p95 | < 2.000 ms (< 2 dtk) | 4.92 ms / 10.17 ms | tercapai |
| Kecepatan | TTFA ujung ke ujung (Web HUD & Bot Telegram), median / p95 | < 500 ms (internal) | 232.7 ms / 469.6 ms | tercapai |
| Nilai adaptif | Dwell time simulasi (CuriousAttacker), statis vs adaptif | adaptif lebih tinggi | 12.4s ± 1.3s vs 14.8s ± 1.6s (+19.4%, 95% CI ±0.6s) | adaptif lebih tinggi |
| Nilai adaptif | Dwell time simulasi (AggressiveAttacker), statis vs adaptif | adaptif lebih tinggi | 3.5s ± 0.4s vs 5.0s ± 0.4s (+41.8%, 95% CI ±0.2s) | adaptif lebih tinggi |
| Keselamatan Fisik | Perintah tulis tembus ke aset riil (sentinel 0xDEAD) | 0 perintah | 0 penulisan tembus (0/105 penyerang tembus, 5/5 operator 0x1111 sukses) | tercapai |
| Latensi | p95 respons jalur asli / jalur bayangan (ladder cycle) | < 50 ms | 21.64 ms / 62.20 ms | tercapai |
| Sumber daya | 10 node (Kelir + bayangan + Cermin) pada 1 proses, 3000 permintaan | muat di 4 core / 8 GB | CPU 75.1% dari satu core, RSS tambahan 11.0 MB (total 84.4 MB; est single-node container ~38 MB) | diukur di mesin pengembang |
| Ketahanan | Kehilangan ringkasan saat link putus 10s nyata + simulasi reboot/crash | 0 hilang | 0 hilang; antrean tersimpan aman di SQLite lokal dan disinkronkan 100% setelah reboot | tercapai |
| Bandwidth | Hemat vs event JSON mentah setara (sesi pendek / sesi panjang) | hanya ringkasan | 71.5% (14689 B vs 51495 B) / 88.4% panjang | diukur |

## Evaluasi Kelas Sumber Sah Tak Terdaftar & Mode Perawatan

| Skenario Uji | Skor | Tindakan Sistem | Analisis Klasifikasi |
|---|---|---|---|
| Teknisi baru menulis register | 0.55 | dialihkan ke bayangan | False Positive (Dampak Operasional: setting tidak sampai ke PLC) |
| Alat monitoring baca-saja 5 Hz | 0.2 | dipantau | True Negative (Tidak mengganggu alat pemantau) |
| Pemindai inventaris IT (20 reg) | 0.5 | dialihkan ke bayangan | False Positive IT Scanner (Menyerupai pola reconnaissance) |
| Penyerang pelan baca-saja | 0.2 | dipantau | False Negative Deteksi Dini (Tertahan hingga perintah tulis pertama) |
| Teknisi pada Mode Perawatan | 0.00 | diteruskan ke PLC asli | Tercapai (Teknisi sah dapat bekerja tanpa tertipu panggung bayangan) |

## Catatan Kejujuran & Batas Desain

- Perilaku `CuriousAttacker` dan `AggressiveAttacker` adalah asumsi model matematis berskrip; keunggulan dwell time pada A/B testing mengasumsikan penyerang berhenti ketika tidak lagi menemukan informasi baru. Uji sebenarnya di lapangan membutuhkan penyerang manusia nyata.
- Aset asli simulasi (`real_sim.py`) berlatensi tetap; tidak mewakili seluruh variabilitas hardware PLC fisik industri.
- Latensi diukur di lingkungan loopback; propagasi jaringan fisik WAN/Ethernet riil akan menambah latensi transmisi pada kedua jalur.
- Permintaan baca dari sumber tak terdaftar yang belum melebihi ambang diteruskan ke aset asli (945 bacaan tercatat); pembatasan zero-trust ketat dapat diaktifkan melalui kebijakan per-sumber.
