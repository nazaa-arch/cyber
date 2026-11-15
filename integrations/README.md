# Integrasi WAYANG dengan Wazuh dan Suricata

WAYANG tidak menggantikan SOC satuan. Ia menjadi lapisan tipuan yang **menerima
deteksi** dari Suricata dan **mengirim bukti** ke Wazuh.

```
 Suricata (SPAN segmen OT)                 Wazuh SIEM satuan
   │ eve.json: alert                          ▲ wayang-alerts.json (JSON per baris)
   ▼                                          │ rule 100700-100711
 EveWatcher ──► IdsWatchlist ──► KELIR ──► Pipeline (hash-chain, ATT&CK ICS) ──► WazuhExporter
                                   │
                                   └─► rulegen.suricata_rules ──► draf rule (persetujuan Dalang) ──► Suricata
```

Ketiga arah ini mati secara bawaan. Masing-masing menyala lewat variabel lingkungan.
Jalur Modbus tidak bergantung pada integrasi: kalau berkas EVE hilang atau rusak,
Kelir tetap bekerja seperti biasa.

## 1. Suricata → WAYANG (deteksi memicu tipuan)

| Variabel | Bawaan | Fungsi |
|---|---|---|
| `WAYANG_SURICATA_EVE` | (kosong) | Jalur `eve.json` Suricata |
| `WAYANG_IDS_MAX_SEVERITY` | `2` | Hanya alert dengan severity ≤ nilai ini (1 = terberat) |
| `WAYANG_IDS_TTL_S` | `900` | Lama tanda berlaku per IP (detik) |
| `WAYANG_IDS_IGNORE` | (kosong) | IP yang tidak pernah ditandai, dipisah koma (mis. sensor sendiri) |
| `WAYANG_IDS_OPERATOR_MODE` | `alert` | Perlakuan operator terdaftar yang ditandai: `alert` atau `divert` |
| `WAYANG_IDS_FROM_START` | (kosong) | `1` = baca eve.json dari awal (lab); bawaan mulai dari ujung |

Perilakunya:
- **Sumber tak terdaftar yang ditandai** langsung dilayani bayangan sejak frame
  pertama, juga saat `zero_trust` dimatikan. Alasannya menyebut signature dan sid
  Suricata, lalu masuk rantai hash.
- **Operator terdaftar yang ditandai** (indikasi workstation-nya dikuasai):
  - mode `alert` (bawaan): sesi tetap ke aset asli, dan Dalang mendapat peringatan
    `ids_flag_operator`. Mengalihkan operator sah memutus kendali proses nyata,
    jadi keputusan itu diserahkan ke manusia.
  - mode `divert`: sesi dikarantina ke bayangan. Gunakan untuk lab, atau bila
    komandan memutuskan karantina.
- Mode perawatan (`maintenance_mode`) mematikan efek tanda IDS.

Rule statis untuk segmen OT ada di [`suricata/wayang-ot.rules`](suricata/wayang-ot.rules)
(sid 9799001–9799003): tulis Modbus dan Read Device Identification dari host
bukan operator, serta pemindaian port 502.

## 2. WAYANG → Wazuh (bukti masuk SIEM)

| Variabel | Bawaan | Fungsi |
|---|---|---|
| `WAYANG_WAZUH_LOG` | (kosong) | Jalur berkas JSON per baris, mis. `/var/log/wayang/wayang-alerts.json` |
| `WAYANG_WAZUH_ALL` | (kosong) | `1` = sertakan juga baca register mentah (bawaan dibuang karena ramai) |

Pemasangan di Wazuh:
1. Salin [`wazuh/wayang_rules.xml`](wazuh/wayang_rules.xml) ke `/var/ossec/etc/rules/` di manajer.
2. Tempel [`wazuh/ossec_localfile.xml`](wazuh/ossec_localfile.xml) di akhir `ossec.conf` agen pada mesin WAYANG.
3. Restart agen dan manajer.

| Rule | Level | Kejadian |
|---|---|---|
| 100701 | 6 | Sumber tak terdaftar membaca aset OT |
| 100702 | 10 | Sesi dialihkan ke bayangan |
| 100703 | 12 | Perintah tulis tertahan di bayangan (PLC asli aman) |
| 100704 | 12 | Honeytoken dipakai |
| 100705 | 8 | Kredensial bawaan di HMI umpan |
| 100706 | 8 | Blokir otomatis L3 |
| 100707 | 12 | Operator melanggar kebijakan per-sumber |
| 100708 | 5 | Tanda Suricata diterima WAYANG |
| 100709 | 13 | Operator terdaftar ditandai Suricata |
| 100710 | 8 | Rekomendasi alihkan (otonomi rendah) |
| 100711 | 13 | Tiga pengalihan dari IP sama dalam 5 menit |

Setiap baris menyertakan `srcip` di tingkat atas, sehingga `same_source_ip` dan
active response Wazuh bisa langsung dipakai. Baris itu juga membawa `wayang.hash`
dan `wayang.event_id`, jadi alert Wazuh bisa dicocokkan kembali ke rantai bukti
Merkle (BAP-FD).

## 3. WAYANG → Suricata (bayangan menjadi benteng)

`engine.rulegen.suricata_rules()` membuat draf rule per sumber yang menyentuh
bayangan: tulis Modbus, koneksi baru ke port OT, dan Read Device Identification
bila teknik T0888 teramati. Nomor sid-nya deterministik (9.700.000–9.799.999).
Draf ini ikut di paket persetujuan Dalang (`bundle["suricata"]`) dan tersedia di
`GET /api/tactical/rules/suricata.rules`.
Aksi bawaan `alert`; ganti ke `drop` hanya pada Suricata inline (IPS) setelah disetujui.
Input divalidasi: loopback, IP daftar putih, dan nama satuan berkarakter aneh ditolak.

## Lab dan bukti uji

```bash
python integrations/lab/make_pcap.py                                   # pcap sintetis
docker compose -f integrations/lab/docker-compose.yml run --rm suricata # Suricata 8.0.8 asli
python integrations/lab/demo_alur.py                                    # Suricata -> WAYANG -> berkas Wazuh
docker compose -f integrations/lab/docker-compose.yml up -d --build wazuh-manager
```

Hasil uji 15 Nov 2026 (Windows 11, Docker Desktop):
- **Suricata 8.0.8**: 6 rule dimuat, 0 gagal (3 statis + 3 dinamis dari `rulegen`).
  Pcap lab: HMI sah 10.10.5.30 tidak memicu alert. Penyerang 10.10.5.90 memicu
  sid 9799001 (statis) serta 9778010 dan 9778011 (dinamis).
- **Alur demo**: tanda Suricata membuat sesi dialihkan dengan `zero_trust` mati,
  PLC asli menerima 0 tulis, rantai hash utuh, dan 6 baris JSON siap dibaca Wazuh.
- **Wazuh 4.14.9** (`wazuh-logtest`, 16 baris: 6 dari demo + 10 contoh per jenis event):
  rule dimuat tanpa error, decoder JSON mengenali `srcip`, dan setiap rule 100700–100711
  memicu alert sesuai rancangan. Rule korelasi 100711 (level 13) aktif pada pengalihan
  ketiga dari IP yang sama. Blok `<mitre>` pada 100704/100705 terpetakan ke T1078 dan T1078.001.
- **Tes unit**: `tests/test_integrations.py` (17 tes).

Batasan:
- Pcap lab adalah rekaman buatan, bukan lalu lintas jaringan satuan.
- Di demo satu laptop, IP penyerang dari alert Suricata dipetakan ke loopback.
  Berkas `eve-demo.json` menandainya dengan `x_wayang_demo`.
- Belum diuji pada Suricata yang mengamati SPAN fisik maupun pada agen Wazuh di mesin terpisah.
