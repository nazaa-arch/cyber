# Panduan Konfigurasi Domain: cyber.steamcraft.online (SSL Let's Encrypt)

Dokumen ini merinci status sertifikat SSL dan langkah menghubungkan URL publik `https://cyber.steamcraft.online` ke mesin pertahanan siber **WAYANG Dalang Console**.

---

## 🔒 1. Status Verifikasi Domain & SSL

Pengecekan teknis terhadap domain `cyber.steamcraft.online` telah dilakukan:
- **DNS Record**: `cyber.steamcraft.online` ➔ `163.223.227.38` (Hosting Anymhost).
- **Status Port HTTPS**: Port 443 terbuka dan merespons `200 OK`.
- **Sertifikat SSL**: **SUDAH TERPASANG & VALID**
  - Penerbit (*Issuer*): **Let's Encrypt (YR2)**
  - Nama Domain (*Common Name*): `cyber.steamcraft.online`
  - SAN: `cyber.steamcraft.online`
  - Protokol: TLS 1.3 / HTTPS terenkripsi penuh.

---

## ⚡ 2. Mengapa Ngrok Custom Domain Memerlukan Gateway?

Perintah `ngrok http 8080 --url https://cyber.steamcraft.online` mengembalikan pesan sistem:
> `ERR_NGROK_314: Only paid plans may create endpoints with custom hostnames. Failed to create an endpoint with custom hostname for account on Free plan.`

Paket gratis Ngrok tidak mengizinkan pemakaian custom hostname secara langsung pada klien ngrok. Namun, karena Anda **sudah memiliki hosting Anymhost aktif dengan SSL Let's Encrypt terpasang**, kita menggunakan solusi arsitektur **Reverse Proxy Gateway**.

---

## 🛠️ 3. Langkah 1 Menit Menghubungkan (cPanel Anymhost)

Kami telah menyiapkan berkas gateway yang siap diunggah di folder:
`c:\Kebutuhan Data Pribadi\Kartika Cyber\wayang\hosting_gateway\`

### Langkah-langkah:
1. Buka cPanel Anymhost Anda melalui peramban web.
2. Masuk ke menu **File Manager**.
3. Buka direktori root untuk subdomain `cyber.steamcraft.online` (biasanya berada di `public_html/cyber` atau direktori terpisah sesuai konfigurasi subdomain Anda).
4. Unggah 2 berkas berikut:
   - `index.php` (dari folder `hosting_gateway/index.php`)
   - `.htaccess` (dari folder `hosting_gateway/.htaccess`)
5. **Selesai!**
   Buka peramban di: **`https://cyber.steamcraft.online`**
   - URL peramban akan menampilkan `https://cyber.steamcraft.online`.
   - Simbol gembok SSL hijau/aman aktif.
   - Terhubung langsung ke mesin pertahanan WAYANG Dalang Console di laptop Anda.

---

## 📡 4. Konfigurasi Sistem Internal WAYANG

Sistem WAYANG pada laptop ini telah dikonfigurasi secara otomatis:
- `.env`: `CONSOLE_URL=https://cyber.steamcraft.online`
- Bot Telegram (`@Dalangwayangbot`): Semua tombol persetujuan dan notifikasi taktis kini mengarah ke `https://cyber.steamcraft.online`.
- Berita Acara Forensik Militer (BAP-FD): Tautan bukti digital mencantumkan `https://cyber.steamcraft.online`.
