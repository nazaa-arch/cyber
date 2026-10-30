"""Penilai sesi Kelir (Bab 9.1 dan 9.3) dengan Kebijakan Granular Per-Sumber.

S(s) = sum_i w_i * f_i(s),  sum w_i = 1;  alihkan <=> S(s) >= theta_d
Transparan dan dapat dijelaskan: setiap keputusan disertai alasan terbaca.

Prinsip Zero Trust ICS:
Daftar putih IP bukan identitas tunggal. Sumber terdaftar (operator pos) tetap
dibatasi oleh kebijakan operasional granular (Unit ID, Function Code, rentang
register tulis, dan laju maksimum polling). Pelanggaran batas kendali dialihkan
ke panggung bayangan.

Invarian Keselamatan Kritis:
Perintah tulis dari sumber tak terdaftar (unlisted write) SELALU dialihkan ke
panggung bayangan tanpa bergantung pada bobot heuristik.
"""
from __future__ import annotations

from dataclasses import dataclass, field
import typing

# Bobot awal dari penilaian ahli; fungsi tulis bobot tertinggi (Bab 9.3).
DEFAULT_WEIGHTS = {
    "unlisted_source": 0.20,
    "write_function": 0.35,
    "sequential_scan": 0.20,
    "default_cred": 0.15,
    "abnormal_rate": 0.10,
}
DEFAULT_THRESHOLD = 0.5

MODBUS_WRITE_FUNCS = {5, 6, 15, 16}


def parse_register_spec(spec) -> set[int]:
    """Parse spesifikasi register menjadi himpunan nomor register yang dinormalisasi.
    Mendukung integer, rentang (range), list/set/tuple, dan string rentang seperti '40001-40020'.
    Menormalisasi alamat PDU berbasis 0 (0..9999) dan alamat register PLC berbasis 1 (40001..49999).
    """
    if spec is None:
        return set()
    regs = set()
    if isinstance(spec, str):
        if "-" in spec:
            p1, p2 = spec.split("-", 1)
            regs.update(range(int(p1.strip()), int(p2.strip()) + 1))
        elif "," in spec:
            for item in spec.split(","):
                regs.update(parse_register_spec(item.strip()))
        else:
            regs.add(int(spec.strip()))
    elif isinstance(spec, (list, tuple, set, range)):
        for item in spec:
            regs.update(parse_register_spec(item))
    elif isinstance(spec, int):
        regs.add(spec)

    # Sinkronisasi dua representasi alamat Modbus:
    # 0-indexed PDU wire offset dan 40001-indexed PLC holding register
    expanded = set(regs)
    for r in regs:
        if 40001 <= r <= 49999:
            expanded.add(r - 40001)
        elif 0 <= r <= 9999:
            expanded.add(r + 40001)
    return expanded


@dataclass
class SourcePolicy:
    """Kebijakan operasional granular untuk sumber operator terdaftar."""
    name: str = "operator"
    source: str = ""
    allow_units: set[int] = field(default_factory=set)
    allow_functions: set[int] = field(default_factory=set)
    allow_write_registers: set[int] = field(default_factory=set)
    max_rate_hz: float = 10.0
    on_violation: str = "divert"  # "divert" (alihkan ke bayangan) atau "drop" (buang)


@dataclass
class Signals:
    """Lima sinyal bernilai 0..1."""
    unlisted_source: float = 0.0
    write_function: float = 0.0
    sequential_scan: float = 0.0
    default_cred: float = 0.0
    abnormal_rate: float = 0.0


@dataclass
class Decision:
    score: float
    divert: bool
    reason: str
    signals: Signals = field(default_factory=Signals)


class SessionScorer:
    def __init__(self, whitelist: set[str] | None = None,
                 policies: dict[str, dict] | list[dict] | None = None,
                 weights: dict[str, float] | None = None,
                 threshold: float = DEFAULT_THRESHOLD,
                 maintenance_mode: bool = False):
        self.whitelist = set(whitelist or ())
        self.policies: dict[str, SourcePolicy] = {}
        self.maintenance_mode = maintenance_mode
        if policies:
            self.load_policies(policies)
        for pol in self.policies.values():
            if pol.source:
                self.whitelist.add(pol.source)

        self.weights = weights or dict(DEFAULT_WEIGHTS)
        assert abs(sum(self.weights.values()) - 1.0) < 1e-9, "bobot harus berjumlah 1"
        self.threshold = threshold

    def load_policies(self, raw_policies: dict | list):
        items = []
        if isinstance(raw_policies, dict):
            for k, v in raw_policies.items():
                if isinstance(v, dict):
                    pol_dict = dict(v)
                    pol_dict.setdefault("name", k)
                    if "source" not in pol_dict:
                        pol_dict["source"] = k
                    items.append(pol_dict)
        elif isinstance(raw_policies, list):
            items = raw_policies

        for item in items:
            name = item.get("name", "operator")
            src = item.get("source", "")
            allow = item.get("allow", {})
            u = allow.get("unit")
            allow_units = set(u) if isinstance(u, (list, tuple, set)) else ({u} if u is not None else set())
            f = allow.get("functions")
            allow_funcs = set(f) if isinstance(f, (list, tuple, set)) else ({f} if f is not None else set())
            w_regs = parse_register_spec(allow.get("write_registers"))
            max_rate = float(item.get("max_rate_hz", allow.get("max_rate_hz", 10.0)))
            on_violation = item.get("on_violation", "divert")
            self.policies[src] = SourcePolicy(
                name=name,
                source=src,
                allow_units=allow_units,
                allow_functions=allow_funcs,
                allow_write_registers=w_regs,
                max_rate_hz=max_rate,
                on_violation=on_violation
            )
            if src:
                self.whitelist.add(src)

    _load_policies = load_policies

    def check_source_policy(self, src: str, unit: int, req, req_rate_hz: float = 0.0) -> tuple[bool, str | None]:
        """
        Memeriksa apakah permintaan dari sumber terdaftar memenuhi kebijakan per-sumber.
        Mengembalikan (allowed: bool, violation_reason: str | None).
        """
        if self.maintenance_mode:
            return True, None

        if src not in self.policies:
            return True, None

        pol = self.policies[src]
        if pol.allow_units and unit not in pol.allow_units:
            return False, f"Unit ID {unit} tidak diizinkan untuk {pol.name}"

        fc = getattr(req, "fc", 0)
        if pol.allow_functions and fc not in pol.allow_functions:
            act = getattr(req, "action", str(fc))
            return False, f"Fungsi Modbus {fc} ({act}) tidak diizinkan untuk {pol.name}"

        if getattr(req, "is_write", False) and pol.allow_write_registers:
            addr = getattr(req, "addr", 0)
            reg = getattr(req, "register", addr + 40001)
            qty = getattr(req, "qty", 1)
            for offset in range(qty):
                cur_addr = addr + offset
                cur_reg = reg + offset
                if cur_addr not in pol.allow_write_registers and cur_reg not in pol.allow_write_registers:
                    return False, f"Tulis ke register {cur_reg} (offset {cur_addr}) di luar rentang {pol.name}"

        if pol.max_rate_hz and req_rate_hz > pol.max_rate_hz:
            return False, f"Laju permintaan {req_rate_hz:.1f} Hz melebihi batas {pol.max_rate_hz:.1f} Hz untuk {pol.name}"

        return True, None

    def score(self, src: str, modbus_funcs: list[int] | None = None,
              scan_targets: int = 0, scan_window_s: float = 0.0,
              default_cred_attempts: int = 0,
              req_rate_hz: float = 0.0, legit_rate_hz: float = 5.0) -> Decision:
        # 1. Mode perawatan: bypass seluruh pengalihan untuk teknisi sah
        if self.maintenance_mode:
            return Decision(0.0, False, "mode perawatan aktif: pengalihan dinonaktifkan")

        # 2. Sumber terdaftar dengan kebijakan per-sumber
        if src in self.policies:
            p = self.policies[src]
            funcs = modbus_funcs or []
            bad = sorted(f for f in funcs if p.allow_functions and f not in p.allow_functions)
            rate_violation = (req_rate_hz > p.max_rate_hz) if p.max_rate_hz else False
            if bad or rate_violation:
                reasons = []
                if bad:
                    reasons.append(f"fungsi terlarang {bad}")
                if rate_violation:
                    reasons.append(f"laju {req_rate_hz:.1f} Hz melebihi batas {p.max_rate_hz:.1f} Hz")
                return Decision(1.0, True, f"dialihkan karena: sumber terdaftar melanggar kebijakan ({', '.join(reasons)})")
            return Decision(0.0, False, "sesuai kebijakan operator")

        # 3. Sumber di daftar putih tanpa kebijakan khusus
        if src in self.whitelist:
            return Decision(0.0, False, "sumber ada di daftar putih")

        # 4. Sumber tak terdaftar: hitung sinyal heuristik
        funcs = modbus_funcs or []
        s = Signals(
            unlisted_source=1.0,
            write_function=1.0 if any(f in MODBUS_WRITE_FUNCS for f in funcs) else 0.0,
            sequential_scan=min(1.0, scan_targets / 10.0),
            default_cred=min(1.0, default_cred_attempts / 3.0),
            abnormal_rate=min(1.0, max(0.0, req_rate_hz / legit_rate_hz - 1.0)),
        )
        total = sum(self.weights[k] * getattr(s, k) for k in self.weights)

        parts = []
        if s.write_function:
            parts.append("tulis register dari sumber tak terdaftar")
        if s.sequential_scan:
            parts.append(f"{scan_targets} pemindaian dalam {scan_window_s:.0f} detik")
        if s.default_cred:
            parts.append(f"{default_cred_attempts} percobaan kredensial bawaan")
        if s.abnormal_rate:
            parts.append("laju di luar pola polling sah")
        if not parts:
            parts.append("sumber tak terdaftar")

        # Invarian keselamatan kritis: perintah tulis dari sumber tak terdaftar SELALU dialihkan
        # tanpa bergantung pada bobot sinyal lainnya.
        divert = (s.write_function > 0.0) or (total >= self.threshold)
        verb = "dialihkan" if divert else "dipantau"
        return Decision(total, divert, f"{verb} karena: " + " + ".join(parts), s)
