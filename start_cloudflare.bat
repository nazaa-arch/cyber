@echo off
title WAYANG - Cloudflare Edge Secure Tunnel
cd /d "%~dp0"
echo ======================================================================
echo    WAYANG C4ISR: CLOUDFLARE EDGE SECURE TUNNEL (ZERO-TRUST)
echo    Menghubungkan Konsol Pertahanan ke Jaringan Global Cloudflare Edge
echo ======================================================================
echo.
echo Membuka koneksi QUIC HTTP/3 ke Cloudflare Edge...
deploy\cloudflared.exe tunnel --url http://127.0.0.1:8080
pause
