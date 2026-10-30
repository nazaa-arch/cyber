#!/usr/bin/env bash
# WAYANG Taktis - Normalisasi Sidik Jari TCP RTOS Schneider Modicon M221
# Script ini dijalankan pada mini-PC / edge gateway taktis Linux.

set -euo pipefail

echo "[*] Mengonfigurasi parameter TCP kernel Linux untuk penyamaran RTOS..."

# 1. Nonaktifkan TCP Timestamps (mencegah kebocoran uptime host & ketidaksesuaian sidik jari RTOS)
sysctl -w net.ipv4.tcp_timestamps=0

# 2. Nonaktifkan TCP Selective ACK (SACK tidak didukung oleh microcontroller RTOS M221)
sysctl -w net.ipv4.tcp_sack=0

# 3. Nonaktifkan TCP Window Scaling (PLC industri menggunakan ukuran jendela tetap)
sysctl -w net.ipv4.tcp_window_scaling=0

# 4. Set ukuran buffer TCP default ke 8192 bytes (khas Schneider Modicon)
sysctl -w net.ipv4.tcp_rmem="8192 8192 8192"
sysctl -w net.ipv4.tcp_wmem="8192 8192 8192"

# 5. Normalisasi IP TTL ke 64 menggunakan iptables mangle
iptables -t mangle -A POSTROUTING -p tcp --sport 502 -j TTL --ttl-set 64 || true

# 6. Set TCP MSS tetap 1460 bytes
iptables -t mangle -A POSTROUTING -p tcp --sport 502 --tcp-flags SYN,ACK SYN,ACK -j TCPMSS --set-mss 1460 || true

echo "[+] Konfigurasi selesai. Sidik jari nmap -O dan p0f diselaraskan ke profil RTOS PLC."
