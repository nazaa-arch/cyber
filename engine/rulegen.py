"""Generator Aturan (Bab 4.1 Pilar 4, 9.5): Bayangan -> Benteng.

Keluaran dari satu sesi: aturan deteksi gaya Sigma, IOC (STIX 2.1 sederhana),
draf nftables, dan rekomendasi hardening. Tidak ada yang diterapkan otomatis;
semua draf menunggu persetujuan Dalang.
"""
from __future__ import annotations

import ipaddress
import re
import time
import uuid

import yaml

_NS = uuid.UUID("5a0d3b6e-7c1f-4f0e-9d6a-0a7e17a9a001")
_SAFE = re.compile(r"^[A-Za-z0-9_.:-]+$")

# teknik -> (id aturan, judul, deskripsi deteksi)
RULES = {
    "write": ({"T0855", "T0836", "T0831"},
              "wayang_modbus_write_non_operator",
              "Peringatkan bila ada fungsi tulis Modbus dari alamat di luar daftar operator ke subnet OT.",
              {"fc": [5, 6, 15, 16]}),
    "scan": ({"T0846", "T0840"},
             "wayang_ot_sequential_scan",
             "Peringatkan bila satu sumber membaca register/unit berurutan lebih dari ambang dalam jendela singkat.",
             {"pola": "baca berurutan", "ambang": 10}),
    "default_cred": ({"T0812"},
                     "wayang_default_credential_attempt",
                     "Peringatkan percobaan login memakai kredensial bawaan pada panel HMI/CCTV.",
                     {"login": ["admin:admin"]}),
    "valid_acct": ({"T0859"},
                   "wayang_leaked_credential_reuse",
                   "Peringatkan penggunaan kredensial/token yang bocor dari dokumen umpan.",
                   {"token_pattern": "HT[0-9a-f]{12}"}),
    "devid": ({"T0888"},
              "wayang_device_identification_probe",
              "Peringatkan permintaan Read Device Identification (fc 43) dari sumber tak terdaftar.",
              {"fc": [43]}),
    "read": ({"T0801", "T0861", "T0845", "T0802"},
             "wayang_unlisted_process_read",
             "Peringatkan pembacaan data proses/konfigurasi oleh sumber di luar daftar operator.",
             {"fc": [1, 2, 3, 4]}),
}

HARDENING = {
    "T0812": "Nonaktifkan kredensial bawaan pada panel HMI/CCTV terkait.",
    "T0859": "Cabut kredensial/token yang bocor dan putar ulang semua rahasia yang sejenis.",
    "T0855": "Batasi fungsi tulis Modbus hanya dari daftar sumber operator (ACL pada segmen OT).",
    "T0846": "Segmentasi jaringan: batasi pemindaian dari segmen IT ke segmen OT.",
    "T0888": "Batasi akses fungsi identifikasi perangkat ke alamat manajemen.",
}


def validate_ip(ip: str, whitelist: set[str] | None = None,
                allow_loopback: bool = False) -> ipaddress._BaseAddress:
    a = ipaddress.ip_address(ip)
    if (a.is_loopback and not allow_loopback) or a.is_multicast or a.is_unspecified \
            or (a.is_reserved and not a.is_private):
        raise ValueError(f"alamat tidak layak diblokir: {ip}")
    if whitelist and ip in whitelist:
        raise ValueError(f"alamat ada di daftar putih: {ip}")
    return a


def sigma_rules(summary: dict) -> list[dict]:
    seen = set(summary.get("techniques", []))
    out = []
    for key, (techs, rid, desc, sel) in RULES.items():
        hit = sorted(seen & techs)
        if not hit:
            continue
        out.append({
            "title": rid, "id": str(uuid.uuid5(_NS, rid)), "status": "experimental",
            "description": desc, "author": "WAYANG Generator Aturan",
            "date": time.strftime("%Y-%m-%d"),
            "tags": [f"attack.ics.{t.lower()}" for t in hit],
            "logsource": {"product": "ot_network", "service": "modbus_tcp"},
            "detection": {"selection": sel,
                          "filter_operator": {"src": "daftar_operator"},
                          "condition": "selection and not filter_operator"},
            "falsepositives": ["operator baru yang belum masuk daftar putih"],
            "level": "high" if key in ("write", "valid_acct") else "medium",
        })
    return out


def _is_test_net(ip: ipaddress.IPv4Address | ipaddress.IPv6Address) -> bool:
    if ip.version == 4:
        return any(ip in ipaddress.ip_network(n) for n in ("192.0.2.0/24", "198.51.100.0/24", "203.0.113.0/24"))
    return False


def ioc_bundle(summary: dict) -> dict:
    now = time.strftime("%Y-%m-%dT%H:%M:%S.000Z", time.gmtime())
    first_wall = summary.get("first_wall")
    if first_wall:
        valid_from = time.strftime("%Y-%m-%dT%H:%M:%S.000Z", time.gmtime(first_wall))
    else:
        valid_from = now

    objs = []
    src = summary.get("src", "")
    try:
        ip = ipaddress.ip_address(src)
    except ValueError:
        ip = None

    # Saring IOC: saring bila loopback atau alamat privat RFC 1918 internal, tetapi izinkan Test-Net / ancaman publik
    if ip and not (ip.is_loopback or (ip.is_private and not _is_test_net(ip))):
        kind = "ipv4-addr" if ip.version == 4 else "ipv6-addr"
        objs.append({
            "type": "indicator", "spec_version": "2.1",
            "id": "indicator--" + str(uuid.uuid5(_NS, summary["src"] + summary["session"])),
            "created": now, "modified": now, "valid_from": valid_from,
            "name": f"Sumber menyentuh bayangan ({summary.get('satuan', 'TNI-AD')})",
            "pattern": f"[{kind}:value = '{summary['src']}']", "pattern_type": "stix",
            "labels": ["wayang-decoy-touch"],
            "x_wayang_techniques": summary.get("techniques", []),
            "x_wayang_fingerprint": summary.get("fingerprint", {}).get("ngrams", [])[:20],
        })

    for tok in sorted(summary.get("honeytokens_planted", [])):
        objs.append({
            "type": "indicator", "spec_version": "2.1",
            "id": "indicator--" + str(uuid.uuid5(_NS, tok)),
            "created": now, "modified": now, "valid_from": valid_from,
            "name": "Honeytoken terbawa penyerang",
            "pattern": f"[x-wayang-token:value = '{tok}']", "pattern_type": "stix",
            "labels": ["wayang-honeytoken"]})
    return {"type": "bundle", "id": "bundle--" + str(uuid.uuid5(_NS, summary["session"])),
            "objects": objs}


def nftables_draft(src: str, ports=(502,), ttl: str = "15m",
                   whitelist: set[str] | None = None, allow_loopback: bool = False) -> str:
    a = validate_ip(src, whitelist, allow_loopback)
    for p in ports:
        if not isinstance(p, int) or not 1 <= p <= 65535:
            raise ValueError("port tidak valid")
    fam = "ipv4_addr" if a.version == 4 else "ipv6_addr"
    sel = "ip" if a.version == 4 else "ip6"
    pl = ", ".join(str(p) for p in ports)
    return (
        "# DRAF WAYANG - BELUM DITERAPKAN. Butuh tinjauan dan persetujuan Dalang.\n"
        "table inet wayang_draft {\n"
        f"  set blocked_{a.version} {{\n    type {fam}\n    flags timeout\n"
        f"    elements = {{ {a} timeout {ttl} }}\n  }}\n"
        "  chain input {\n    type filter hook input priority -10; policy accept;\n"
        f"    {sel} saddr @blocked_{a.version} tcp dport {{ {pl} }} drop\n  }}\n}}\n")


SURICATA_SID_BASE = 9_700_000     # rentang lokal WAYANG: 9.700.000 - 9.799.999


def _suricata_sid(src: str, i: int) -> int:
    import zlib
    return SURICATA_SID_BASE + (zlib.crc32(src.encode()) % 9_999) * 10 + i


def suricata_rules(summary: dict, whitelist: set[str] | None = None,
                   allow_loopback: bool = False, action: str = "alert",
                   ot_ports=(502,), with_header: bool = True) -> str:
    """Draf rule Suricata untuk satu sumber yang menyentuh bayangan.

    action "alert" untuk mode IDS; "drop" hanya berlaku bila Suricata inline (IPS).
    Butuh app-layer modbus aktif (suricata.yaml: app-layer.protocols.modbus.enabled).
    """
    if action not in ("alert", "drop"):
        raise ValueError("action harus 'alert' atau 'drop'")
    for k in ("satuan", "session"):
        if not _SAFE.match(str(summary.get(k, ""))):
            raise ValueError(f"nilai {k} tidak aman")
    a = validate_ip(summary.get("src", ""), whitelist, allow_loopback)
    for p in ot_ports:
        if not isinstance(p, int) or not 1 <= p <= 65535:
            raise ValueError("port tidak valid")
    src, sat, sess = str(a), summary["satuan"], summary["session"]
    ports = ",".join(str(p) for p in ot_ports)
    ports = f"[{ports}]" if len(ot_ports) > 1 else ports
    techs = set(summary.get("techniques", []))
    meta = f"wayang_satuan {sat}, wayang_session {sess}"
    out = []
    if with_header:
        out += ["# DRAF WAYANG - BELUM DITERAPKAN. Butuh tinjauan dan persetujuan Dalang.",
                f"# Sumber {src} menyentuh bayangan {sat} (sesi {sess}).",
                "# Variabel $OT_NET wajib didefinisikan di suricata.yaml (vars.address-groups)."]
    out.append(
        f'{action} modbus {src} any -> $OT_NET {ports} (msg:"WAYANG {sat} - perintah tulis '
        f'Modbus dari sumber penyentuh bayangan"; flow:to_server,established; '
        f'modbus: access write; classtype:attempted-admin; priority:1; '
        f'sid:{_suricata_sid(src, 0)}; rev:1; metadata: {meta}, mitre_technique T0855;)')
    out.append(
        f'{action} tcp {src} any -> $OT_NET {ports} (msg:"WAYANG {sat} - koneksi baru dari '
        f'sumber penyentuh bayangan ke aset OT"; flow:to_server; flags:S,12; '
        f'threshold: type limit, track by_src, count 1, seconds 60; classtype:misc-activity; '
        f'priority:2; sid:{_suricata_sid(src, 1)}; rev:1; metadata: {meta};)')
    if techs & {"T0888"}:
        out.append(
            f'{action} modbus {src} any -> $OT_NET {ports} (msg:"WAYANG {sat} - Read Device '
            f'Identification dari sumber penyentuh bayangan"; flow:to_server,established; '
            f'modbus: function 43; classtype:attempted-recon; priority:2; '
            f'sid:{_suricata_sid(src, 2)}; rev:1; metadata: {meta}, mitre_technique T0888;)')
    return "\n".join(out) + "\n"


def recommendations(summary: dict) -> list[str]:
    out = []
    for t in summary.get("techniques", []):
        r = HARDENING.get(t)
        if r and r not in out:
            out.append(r)
    return out


def covered_techniques(techs) -> set[str]:
    cov = set()
    for tset, *_ in RULES.values():
        cov |= tset
    return set(techs) & cov


def build_bundle(summary: dict, whitelist: set[str] | None = None,
                 allow_loopback: bool = False) -> dict:
    """Satu paket keluaran untuk satu sesi."""
    for k in ("src", "session", "satuan"):
        if not _SAFE.match(str(summary.get(k, ""))):
            raise ValueError(f"nilai {k} tidak aman")
    rules = sigma_rules(summary)
    techs = summary.get("techniques", [])
    return {
        "session": summary["session"],
        "sigma_yaml": yaml.safe_dump_all(rules, allow_unicode=True, sort_keys=False),
        "sigma": rules,
        "ioc": ioc_bundle(summary),
        "nftables": nftables_draft(summary["src"], whitelist=whitelist,
                                   allow_loopback=allow_loopback),
        "suricata": suricata_rules(summary, whitelist=whitelist,
                                   allow_loopback=allow_loopback),
        "hardening": recommendations(summary),
        "ratio_benteng": (len(covered_techniques(techs)) / len(techs)) if techs else 1.0,
    }

