"""Generator Teks (Bab 6.2): log operator, catatan perawatan, dokumen umpan.

Templat deterministik (Jinja2) adalah cadangan utama agar demo tidak
bergantung pada model. Model bahasa lokal kecil (kompatibel Ollama) bersifat
opsional lewat variabel lingkungan OLLAMA_URL; bila gagal, jatuh ke templat.
"""
from __future__ import annotations

import json
import os
import random
import urllib.request

from jinja2 import Environment, StrictUndefined

_env = Environment(undefined=StrictUndefined, autoescape=False, trim_blocks=True)

TEMPLATES = {
    "operator_log": _env.from_string(
        "{% for l in lines %}{{ l.ts }} [{{ l.op }}] {{ l.msg }}\n{% endfor %}"),
    "maintenance_note": _env.from_string(
        "CATATAN PERAWATAN - {{ asset }}\n"
        "Lokasi : {{ location }}\nTanggal: {{ date }}\n"
        "Petugas: {{ tech }}\n"
        "Pekerjaan: {{ job }}\nKeterangan: {{ remark }}\n"),
    "config_backup": _env.from_string(
        "# Cadangan konfigurasi {{ asset }} ({{ vendor }} {{ model }} {{ fw }})\n"
        "[umum]\nnama_aset = {{ asset }}\nlokasi = {{ location }}\n\n"
        "[modbus]\nunit_id = 1\nport = 502\n\n"
        "[akun_layanan]\nuser = {{ svc_user }}\npassword = {{ token }}\n\n"
        "[vpn_cadangan]\nuser = {{ vpn_user }}\nsecret = {{ token }}\n"),
}

_OPS = ["jaga-1", "jaga-2", "tek-listrik", "tek-bbm"]
_JOBS = ["pemeriksaan rutin pompa", "penggantian filter", "kalibrasi sensor level",
         "pengecekan katup", "pembersihan panel"]
_REMARKS = ["kondisi baik", "perlu pemantauan", "suhu normal", "tidak ada temuan"]


def _llm(prompt: str, timeout: float = 8.0) -> str | None:
    url = os.environ.get("OLLAMA_URL")
    if not url and os.environ.get("OLLAMA_ENABLED", "").lower() in ("1", "true", "yes"):
        url = "http://localhost:11434"
    if not url or url.lower() in ("none", "off", "0"):
        return None
    try:
        body = json.dumps({"model": os.environ.get("OLLAMA_MODEL", "qwen2.5:0.5b"),
                           "prompt": prompt, "stream": False}).encode()
        req = urllib.request.Request(url.rstrip("/") + "/api/generate", body,
                                     {"Content-Type": "application/json"})
        with urllib.request.urlopen(req, timeout=timeout) as r:
            return json.loads(r.read()).get("response")
    except Exception:
        return None


def generate(kind: str, seed: int, **ctx) -> str:
    rng = random.Random(seed)
    if kind == "operator_log":
        h = ctx.get("hour", 8)
        lines = []
        for i in range(ctx.get("n", 6)):
            lines.append({"ts": f"{(int(h) - i) % 24:02d}:{rng.randint(0, 59):02d}",
                          "op": rng.choice(_OPS),
                          "msg": rng.choice(["level tangki dicatat", "pompa 1 normal",
                                             "suhu ruang pompa normal",
                                             "pengisian terjadwal selesai",
                                             "serah terima jaga"])})
        lines.sort(key=lambda l: l["ts"])
        ctx = {"lines": lines}
    elif kind == "maintenance_note":
        ctx = {"asset": ctx["asset"], "location": ctx["location"],
               "date": ctx.get("date", "2026-10-01"), "tech": f"Tek-{rng.randint(10, 99)}",
               "job": rng.choice(_JOBS), "remark": rng.choice(_REMARKS)}
        extra = _llm("Tulis satu kalimat catatan perawatan pompa BBM, bahasa Indonesia.")
        if extra:
            ctx["remark"] = extra.strip()[:160]
    elif kind != "config_backup":
        raise KeyError(kind)
    return TEMPLATES[kind].render(**ctx)
