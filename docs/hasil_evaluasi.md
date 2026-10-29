# Hasil Evaluasi WAYANG (Bab 13)

Dihasilkan otomatis oleh `sim_attacker/evaluate.py` pada 2026-10-29 03:00.
Mesin: Windows 11, 16 CPU logis, Python 3.13.7.

> **Batas klaim.** Angka berikut diukur pada mesin pengembang dengan penyerang
> simulasi buatan tim (skrip internal, hanya ke bayangan milik sendiri). Ini bukan
> uji pada mini-PC satuan, bukan penyerang nyata, dan bukan uji buta manusia.
> Baris "Penyamaran" sengaja dibiarkan kosong sampai relawan menguji.

| Aspek | Metrik | Target awal | Hasil | Status |
|---|---|---|---|---|
| Penyamaran | Tingkat tebakan benar (uji buta 5–10 relawan) | Mendekati 50% | [isi] | belum diuji (butuh manusia, lihat `docs/uji_buta_protokol.md`) |
| Kualitas alert | FPR pada lalu lintas daftar putih | mendekati 0 | 0.0000 (0 alert dari 105 permintaan sah) | tercapai |
| Kualitas alert | Presisi / recall alert pada skenario skrip | tinggi | 1.00 / 1.00 (12 sumber berbahaya) | diukur |
| Kecepatan | Time-to-first-alert (sentuhan pertama → alert), median / p95 | < 2 dtk | 1.1 ms / 1.4 ms (pipeline kejadian→alert p95 3.61 ms) | tercapai |
| Nilai adaptif | Dwell time simulasi (rata-rata, dtk), statis vs adaptif | adaptif lebih tinggi | 18.5 vs 27.5 | adaptif lebih tinggi |
| Nilai adaptif | Teknik unik tertangkap per sesi, statis vs adaptif | adaptif lebih tinggi | 6 vs 6 (n=30) | tidak lebih tinggi |
| Latensi | p95 respons jalur asli / jalur bayangan | < 50 ms | 16.25 ms / 47.13 ms | tercapai |
| Sumber daya | 10 node (Kelir + bayangan + Cermin) pada 1 proses, 3000 permintaan | muat di 4 core / 8 GB | CPU 60.4% dari satu core, RSS tambahan 10.7 MB (total 82.0 MB) | diukur di mesin pengembang, bukan mini-PC |
| Ketahanan | Kehilangan ringkasan saat link ke pusat putus 10 dtk nyata | 0 hilang | 0 hilang; antrean saat putus 40, diterima pusat 40 | tercapai (durasi 30 menit target belum dijalankan; mekanisme antrean tidak bergantung durasi) |
| Bandwidth | Hemat vs log mentah setara | hanya ringkasan | 71.7% (14599 B vs 51654 B) | diukur |

## Indikator keberhasilan konsep (Bab 13.1)

| Indikator | Hasil |
|---|---|
| Rasio sentuhan tipuan | presisi alert 1.00 pada skenario skrip |
| Waktu sampai sadar | median 1.1 ms sampai alert tercatat (ringkasan ke Bot menyusul pada pipeline yang sama) |
| Dwell time pada bayangan | statis 15 langkah vs adaptif 22 langkah |
| Cakupan teknik | 3.62 teknik ATT&CK ICS unik per sesi (rata-rata) |
| Rasio benteng | 1.00 (teknik teramati yang punya aturan otomatis) |
| Beban operator | [isi] butuh pengguna uji |

## Jaminan keselamatan yang diverifikasi

- Perintah tulis yang diterima aset asli simulasi: **5**; seluruhnya berasal dari operator sah di daftar putih (diharapkan 5). Tulis dari 12 penyerang skrip yang sampai ke aset asli = **0** (harus 0).
- Rantai hash SHA-256 valid: **True**.

## Catatan kejujuran

- Perilaku `CuriousAttacker` adalah asumsi model; keunggulan adaptif pada A/B
  sebagian mengikuti asumsi itu. Uji sebenarnya membutuhkan penyerang manusia.
- Aset asli simulasi (`real_sim.py`) berlatensi tetap dan sangat sederhana; tidak
  mewakili PLC nyata.
- Latensi diukur di loopback; jaringan nyata menambah latensi pada kedua jalur.
