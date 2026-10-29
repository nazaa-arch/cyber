@echo off
title WAYANG - Dalang Command Center (Kartika Cyber 2026)
cls
echo =====================================================================
echo           WAYANG: ADAPTIVE DECEPTION GRID UNTUK TNI AD
echo        Infrastruktur Pertahanan Siber Terdistribusi IT/OT
echo =====================================================================
echo.
echo [1/3] Menyiapkan environment Python...
set PYTHONPATH=.

echo [2/3] Membuka Peramban ke Dalang Console (http://127.0.0.1:8080)...
start http://127.0.0.1:8080

echo [3/3] Memulai Layanan Dalang Command Center, Kelir Proxy, dan Decoys...
echo Tekan Ctrl+C untuk menghentikan sistem.
echo ---------------------------------------------------------------------
python -m demo --mode full --port 8080
pause
