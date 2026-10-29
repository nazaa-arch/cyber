"""Penilai sesi Kelir (Bab 9.1 dan 9.3).

S(s) = sum_i w_i * f_i(s),  sum w_i = 1;  alihkan <=> S(s) >= theta_d
Transparan dan dapat dijelaskan: setiap keputusan disertai alasan terbaca.
"""
from __future__ import annotations

from dataclasses import dataclass, field

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
                 weights: dict[str, float] | None = None,
                 threshold: float = DEFAULT_THRESHOLD):
        self.whitelist = whitelist or set()
        self.weights = weights or dict(DEFAULT_WEIGHTS)
        assert abs(sum(self.weights.values()) - 1.0) < 1e-9, "bobot harus berjumlah 1"
        self.threshold = threshold

    def score(self, src: str, modbus_funcs: list[int] | None = None,
              scan_targets: int = 0, scan_window_s: float = 0.0,
              default_cred_attempts: int = 0,
              req_rate_hz: float = 0.0, legit_rate_hz: float = 5.0) -> Decision:
        # Operator sah di daftar putih tetap diteruskan ke aset asli.
        if src in self.whitelist:
            return Decision(0.0, False, "sumber ada di daftar putih")

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
        divert = total >= self.threshold
        verb = "dialihkan" if divert else "dipantau"
        return Decision(total, divert, f"{verb} karena: " + " + ".join(parts), s)
