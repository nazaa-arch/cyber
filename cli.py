#!/usr/bin/env python3
"""WAYANG TACTICAL CLI: Alat Komando Operasional Pertahanan Siber TNI AD.

Memberikan kontrol penuh berbasis antarmuka terminal militer untuk:
- Pemantauan status kesiapan operasi pertahanan (DEFCON & Echelon Status)
- Verifikasi matematis integritas log kriptografis (RFC 6962 Merkle Tree)
- Eksekusi simulasi taktis (Recon, ICS Sabotage, Campaign, Phishing)
- Ekspor berkas intelijen siber (BAP-FD, STIX 2.1, Sigma, nftables)
- Perintah penutupan darurat / isolasi pangkalan (Tactical Lockdown)
"""
from __future__ import annotations

import argparse
import json
import sys
import os
import urllib.request
import urllib.error

# Konfigurasi encoding stdout agar aman di terminal Windows cp1252
if hasattr(sys.stdout, "reconfigure"):
    try:
        sys.stdout.reconfigure(encoding="utf-8")
    except Exception:
        pass

API_BASE = "http://127.0.0.1:8080"


def _auth_headers() -> dict:
    t = os.environ.get("WAYANG_ADMIN_TOKEN", "")
    return {"X-Wayang-Token": t} if t else {}


def _get(path: str):
    try:
        req = urllib.request.Request(f"{API_BASE}{path}", headers=_auth_headers())
        with urllib.request.urlopen(req, timeout=5) as res:
            return json.loads(res.read().decode("utf-8"))
    except Exception as e:
        sys.exit(f"[\033[91mERROR\033[0m] Gagal menghubungi Dalang Backend ({API_BASE}): {e}")


def _post(path: str, data=None):
    try:
        body = json.dumps(data).encode("utf-8") if data else b"{}"
        req = urllib.request.Request(f"{API_BASE}{path}", data=body, headers={"Content-Type": "application/json", **_auth_headers()})
        with urllib.request.urlopen(req, timeout=8) as res:
            return json.loads(res.read().decode("utf-8"))
    except Exception as e:
        sys.exit(f"[\033[91mERROR\033[0m] Gagal mengirim perintah: {e}")


def cmd_status(args):
    units = _get("/api/map")
    campaigns = _get("/api/campaigns")
    autonomy = _get("/api/autonomy")

    print("\033[96m" + "=" * 78 + "\033[0m")
    print("\033[97;1m  PUSAT KOMANDO OPERASI PERTAHANAN SIBER IT/OT - TNI ANGKATAN DARAT\033[0m")
    print(f"  Target URL: \033[93mhttps://cyber.steamcraft.online\033[0m  |  Status: \033[92m● REALTIME ACTIVE\033[0m")
    print("\033[96m" + "=" * 78 + "\033[0m\n")

    print(f"\033[1m{'SATUAN / PANGKALAN':<24} {'LEVEL':<8} {'STATUS':<20} {'ROLE OPERASIONAL':<24}\033[0m")
    print("-" * 78)
    for u in units:
        st = u.get("status", "Aman")
        st_color = "\033[92m" if st == "Aman" else ("\033[93m" if st == "Tipuan Disentuh" else "\033[91m")
        print(f"{u['satuan']:<24} {u.get('level', 'KODIM'):<8} {st_color}{st:<20}\033[0m {u.get('role', '')[:24]}")

    print("\n\033[1mKAMPANYE TERKOORDINASI:\033[0m")
    if campaigns:
        for c in campaigns:
            print(f"  \033[91m🚨 {c['id']}\033[0m: {' -> '.join(c['satuan'])} ({c.get('bukti')})")
    else:
        print("  \033[90m(Tidak ada kampanye APT terkoordinasi aktif)\033[0m")
    print()


def cmd_attack(args):
    print(f"[*] Mengirim pemicu simulasi serangan [{args.type}]...")
    res = _post(f"/api/simulate/{args.type}")
    print(f"[\033[92mSUKSES\033[0m] {res.get('msg')}")


def cmd_lockdown(args):
    print(f"[*] Menjalankan TACTICAL LOCKDOWN untuk satuan: {args.satuan}...")
    res = _post(f"/api/tactical/lockdown/{args.satuan}")
    print(f"[\033[92mSELESAI\033[0m] {res.get('msg')}")


def cmd_verify(args):
    print(f"[*] Mengambil bukti integritas Merkle Tree & Hash-Chain satuan: {args.satuan}...")
    chain = _get(f"/api/chain/{args.satuan}")
    merkle = _get(f"/api/chain/{args.satuan}/merkle")

    print(f"  Integritas Rantai: \033[92m{'TERVERIFIKASI (VALID)' if chain.get('ok') else 'INVALID'}\033[0m")
    print(f"  Total Daun Audit : {merkle.get('total_leaves', 0)} events")
    print(f"  Pohon Merkle     : \033[96mRFC 6962 Compliance\033[0m")
    print(f"  Merkle Root      : \033[93m{merkle.get('merkle_root')}\033[0m")
    print(f"  Tanda Tangan HMAC: \033[92m{merkle.get('signature')}\033[0m")
    print(f"  Standar Audit   : RFC 6962 Certificate Transparency")


def cmd_export(args):
    endpoint_map = {
        "bap": "/api/report/latest.docx",
        "stix": "/api/tactical/rules/stix.json",
        "sigma": "/api/tactical/rules/sigma.yml",
        "nftables": "/api/tactical/rules/nftables.conf"
    }
    ep = endpoint_map[args.format]
    out_file = args.out or f"export_{args.format}.{'docx' if args.format == 'bap' else ('json' if args.format == 'stix' else 'txt')}"

    print(f"[*] Mengunduh intelijen format [{args.format.upper()}]...")
    try:
        req = urllib.request.Request(f"{API_BASE}{ep}")
        with urllib.request.urlopen(req, timeout=10) as res:
            content = res.read()
            with open(out_file, "wb") as f:
                f.write(content)
        print(f"[\033[92mSUKSES\033[0m] Berkas tersimpan di: \033[93m{out_file}\033[0m ({len(content)} bytes)")
    except Exception as e:
        sys.exit(f"[\033[91mERROR\033[0m] Gagal ekspor: {e}")


def main():
    p = argparse.ArgumentParser(description="WAYANG Tactical CLI - Cyber Defense Platform TNI AD")
    sub = p.add_subparsers(dest="command", required=True)

    # status
    p_status = sub.add_parser("status", help="Tampilkan status pertahanan pangkalan & DEFCON")
    p_status.set_defaults(func=cmd_status)

    # attack
    p_atk = sub.add_parser("attack", help="Jalankan simulasi serangan uji")
    p_atk.add_argument("--type", choices=["t1", "t2", "campaign", "phishing"], default="t2")
    p_atk.set_defaults(func=cmd_attack)

    # lockdown
    p_lock = sub.add_parser("lockdown", help="Karantina pangkalan seketika")
    p_lock.add_argument("--satuan", default="KODAM-IV-Diponegoro")
    p_lock.set_defaults(func=cmd_lockdown)

    # verify
    p_ver = sub.add_parser("verify", help="Verifikasi integritas rantai hash Merkle")
    p_ver.add_argument("--satuan", default="KODAM-IV-Diponegoro")
    p_ver.set_defaults(func=cmd_verify)

    # export
    p_exp = sub.add_parser("export", help="Ekspor berkas forensik atau intelijen")
    p_exp.add_argument("--format", choices=["bap", "stix", "sigma", "nftables"], default="bap")
    p_exp.add_argument("--out", default=None)
    p_exp.set_defaults(func=cmd_export)

    args = p.parse_args()
    args.func(args)


if __name__ == "__main__":
    main()
