# Keamanan Konsol Dalang & Akses Cloudflare

## 1. Autentikasi Konsol (Token Komando)

Seluruh endpoint `/api/*` dan WebSocket `/ws/live` dilindungi token. Hanya halaman statis (`/`, `/static/*`) dan `/api/auth/*` yang publik; halaman statis akan menampilkan layar **Akses Komando Terbatas**.

| Variabel lingkungan | Fungsi |
| :--- | :--- |
| `WAYANG_ADMIN_TOKEN` | Token tetap. Bila kosong, `run_wayang.py` membuat token acak dan **mencetaknya di log startup**. |
| `WAYANG_AUTH=off` | Mematikan autentikasi (hanya untuk laptop lokal tertutup; peringatan dicetak). |

Mekanisme:
- Login `POST /api/auth/login` → cookie sesi `HttpOnly`, `SameSite=Strict`, `Secure` bila lewat HTTPS, berlaku 12 jam. Cookie berisi HMAC turunan token, bukan token mentah.
- Skrip/CLI memakai header `X-Wayang-Token: <token>` (atau `Authorization: Bearer <token>`); `cli.py` membaca `WAYANG_ADMIN_TOKEN` otomatis.
- Pembatasan percobaan: 5 gagal / 60 detik per IP (memakai `CF-Connecting-IP` bila lewat Cloudflare) → HTTP 429.
- Perbandingan token memakai `hmac.compare_digest` (tahan timing-attack).

> Batasan jujur: ini autentikasi token tunggal bersama, bukan manajemen identitas per-operator. Untuk produksi, tambahkan **Cloudflare Access** (SSO/OTP email) di depan konsol sebagai lapis kedua.

## 2. Cloudflare Tunnel

`start_cloudflare.bat` menjalankan *quick tunnel* (URL acak `*.trycloudflare.com`, **tanpa jaminan uptime**, URL berubah tiap restart) — cocok untuk uji/demo.

Untuk domain tetap (mis. `cyber.steamcraft.online`) gunakan **named tunnel** (butuh akun Cloudflare dan domain yang DNS-nya dikelola Cloudflare):

```powershell
deploy\cloudflared.exe tunnel login
deploy\cloudflared.exe tunnel create wayang
deploy\cloudflared.exe tunnel route dns wayang cyber.steamcraft.online
# config.yml:  tunnel: wayang / ingress: - hostname: cyber.steamcraft.online, service: http://127.0.0.1:8080
deploy\cloudflared.exe tunnel run wayang
```

Lapis tambahan yang disarankan di dasbor Cloudflare: WAF managed rules, Rate Limiting untuk `/api/auth/login`, dan Cloudflare Access.

**Doktrin:** hanya konsol web (HUD) yang lewat Cloudflare. Trafik Modbus/OT (port 15030 dst.) tetap lokal di pangkalan dan **tidak** dipublikasikan.

## 3. Bukti Forensik Persisten

`run_wayang.py` menyimpan basis data sesi/peristiwa per satuan di `data/audit/<satuan>/sessions.db` (atau `WAYANG_DATA_DIR`). ID sesi memuat cap waktu proses agar tidak bertabrakan antar-restart. Gunakan `--fresh` untuk demo bersih (folder sementara, tanpa riwayat lama). Tombol **Reset Tampilan** hanya membersihkan status dasbor — **tidak** menghapus bukti.

Catatan: rantai hash (`HashChain`) di memori dimulai ulang per proses; yang persisten adalah isi peristiwa beserta hash-nya di SQLite.

## 4. Profil Aset Bayangan

| Satuan | Jenis | Register utama (selaras `lakon/*.yaml`) | Efek perintah palsu |
| :--- | :--- | :--- | :--- |
| Depo BBM (Diponegoro, Kostrad) | `bbm` | tangki, tekanan, aliran, suhu, pompa | Pompa mati → aliran/tekanan turun |
| Brawijaya | `genset` | input 10 kW, 11 Hz, 12 suhu; holding 20 `genset_cmd` | Trip → kW, Hz, V jatuh ke ~0 |
| Siliwangi | `cctv` | input 0 sudut palang, 1 kamera, 2 beam; holding 30 `gate_lock_cmd` | Buka → sudut 0→90°, beam bypass |
| MABESAD-Siber | `gateway` | input 0 throughput, 1 tautan, 2 CPU; holding 40 `uplink_enable` | Putus → throughput jatuh |

Panel "Aset Nyata" pada twin-screen dibaca dari **StateMirror** (baca-saja ke simulator/PLC asli); panel "Bayangan" dari nilai yang benar-benar dilihat sesi penyerang. Catatan: "aset asli" pada demo adalah `RealDeviceSim` (simulator), bukan perangkat fisik.
