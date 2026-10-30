@echo off
chcp 65001 >nul
title WAYANG C4ISR - Pusat Komando Pertahanan Siber TNI AD
cls
color 0B

echo ===============================================================================
echo            TENTARA NASIONAL INDONESIA ANGKATAN DARAT (TNI AD)
echo         WAYANG C4ISR: ADAPTIVE DECEPTION GRID UNTUK IT/OT MILITER
echo ===============================================================================
echo.
cd /d "%~dp0"
set PYTHONPATH=.

echo [1/3] Mengaktifkan Tunnel Publik Ngrok (cyber.steamcraft.online)...
start "WAYANG Ngrok Tunnel" /min ngrok http 8080 --url https://revival-majesty-lucrative.ngrok-free.dev

echo [2/3] Membuka Konsol C4ISR di Peramban...
start https://cyber.steamcraft.online
start http://127.0.0.1:8080

echo [3/3] Menjalankan Engine C4ISR Dalang & Kelir Modbus Proxy...
echo.
echo ===============================================================================
echo  SISTEM AKTIF!
echo  - Akses Lokal  : http://127.0.0.1:8080
echo  - Akses Publik : https://cyber.steamcraft.online (SSL Let's Encrypt Aktif)
echo ===============================================================================
echo Tekan Ctrl+C untuk menghentikan sistem.
echo -------------------------------------------------------------------------------
python run_wayang.py --port 8080
pause
