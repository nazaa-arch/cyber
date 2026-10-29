# Protokol Uji Buta Penyamaran (Bab 13)

Uji ini membutuhkan 5–10 relawan IT dan tidak dapat diotomatiskan. Baris "Penyamaran"
pada `hasil_evaluasi.md` tetap `[isi]` sampai uji ini dijalankan.

## Persiapan
1. Jalankan dua target Modbus pada port berbeda: satu bayangan WAYANG, satu simulator
   perangkat "asli" (idealnya PLC sungguhan atau simulator pihak ketiga, bukan `real_sim.py`
   yang latensinya tetap dan terlalu sederhana).
2. Acak penugasan A/B untuk tiap relawan dan catat kuncinya secara terpisah.
3. Relawan hanya boleh memakai klien Modbus standar dan pemindai umum (mis. `nmap`, `mbpoll`).

## Pelaksanaan
- Waktu 20 menit per relawan. Pertanyaan: "Mana yang tipuan? Beri tingkat keyakinan 1–5."
- Catat jawaban dan alasan yang diberikan (ini bahan perbaikan fidelity).

## Penilaian
- Tingkat tebakan benar = benar / total. Target awal: mendekati 50% (acak).
- Dengan n kecil, laporkan juga selang kepercayaan (mis. binomial Clopper-Pearson); 7 dari 10
  tebakan benar belum cukup bukti bahwa tebakan berbeda dari acak.
- Laporkan apa adanya, termasuk bila bayangan terbongkar.

## Etika
- Relawan hanya menguji target milik tim. Tidak ada eksploit atau malware.
