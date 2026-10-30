"""Sesi penyerang: pelacak perilaku bersama Kelir dan bayangan (Bab 9.1, 9.2)."""
from __future__ import annotations

import time
from collections import Counter, deque

from engine.adaptive import AdaptiveEngine

STAGE_RANK = {"reconnaissance": 0, "enumeration": 1,
              "manipulation_attempt": 2, "persistence": 3}
ENUM_ACTIONS = {"read_device_identification", "http_login_default_cred",
                "http_tags", "http_panel"}


class Session:
    def __init__(self, sid: str, src: str, now: float):
        self.id = sid
        self.src = src
        self.first = now
        self.last = now
        self.first_wall = time.time()
        self.req_times: deque[float] = deque(maxlen=300)
        self.reads: set = set()
        self.read_counts: Counter = Counter()
        self.seq = 0
        self.seq_first: float | None = None
        self.last_end = None
        self.last_unit = None
        self.last_table = None
        self.default_cred = 0
        self.stage = "reconnaissance"
        self.engine = AdaptiveEngine()
        self.pinned = False
        self.pin_time: float | None = None
        self.base: dict | None = None      # nilai cermin saat dialihkan
        self.writes: list = []
        self.actions: list = []            # (ts, action) untuk sidik jari
        self.proto_features: set = set()
        self.honeytokens_planted: set = set()
        self.honeytokens_used: set = set()
        self.techniques: set = set()
        self.diverted = False
        self.would_divert = False
        self.pump_on = True
        self.pump_change: float | None = None
        self.tank_hold: float | None = None
        self.events = 0
        self.informed = False

    # --- pengamatan ---
    def observe(self, now: float, action: str, unit=None, table=None,
                addr=None, qty: int = 1, fc=None, is_write: bool = False) -> None:
        self.last = now
        self.req_times.append(now)
        self.actions.append((now, action))
        if len(self.actions) > 500:
            del self.actions[0]
        if fc is not None:
            self.proto_features.add(f"fc:{fc}")
        if unit is not None:
            self.proto_features.add(f"unit:{unit}")
        if table is not None and addr is not None and not is_write:
            key = (unit, table, addr)
            self.reads.add(key)
            self.read_counts[key] += 1
            adjacent = self.last_end is not None and addr == self.last_end \
                and table == self.last_table
            unit_step = self.last_unit is not None and unit is not None \
                and unit == self.last_unit + 1
            if adjacent or unit_step:
                self.seq += 1
                if self.seq_first is None:
                    self.seq_first = now
            self.last_end = addr + qty
            self.last_table = table
            self.last_unit = unit
        self._infer_stage(action, is_write)

    def _infer_stage(self, action: str, is_write: bool) -> None:
        new = self.stage
        if action == "http_config_download":
            new = "persistence"
        elif is_write or action.startswith("write_") or action == "http_write":
            new = "manipulation_attempt"
        elif (len(self.reads) >= 5 or self.seq >= 3 or action in ENUM_ACTIONS):
            new = "enumeration"
        if STAGE_RANK[new] > STAGE_RANK[self.stage]:
            self.stage = new

    def note_default_cred(self) -> None:
        self.default_cred += 1
        self.proto_features.add("cred:default")

    def rate_hz(self, now: float, window: float = 2.0) -> float:
        n = sum(1 for t in self.req_times if now - t <= window)
        return n / window

    def scan_window(self) -> float:
        return (self.last - self.seq_first) if self.seq_first is not None else 0.0

    def intervals(self) -> list[float]:
        ts = [t for t, _ in self.actions]
        return [b - a for a, b in zip(ts, ts[1:])]


class SessionRegistry:
    def __init__(self, idle_s: float = 300.0, prefix: str = "ses", max_sessions: int = 2000):
        self.idle = idle_s
        self.prefix = prefix
        self.max_sessions = max_sessions
        self.by_src: dict[str, Session] = {}
        self.by_id: dict[str, Session] = {}
        self._n = 0

    def prune(self, target_size: int | None = None) -> int:
        """Membersihkan sesi tertua (LRU) saat kapasitas penuh untuk mencegah kehabisan RAM (OOM)."""
        target = target_size if target_size is not None else self.max_sessions
        if len(self.by_id) <= target:
            return 0

        # Prioritaskan pembersihan sesi unpinned yang paling lama idle
        candidates = sorted(
            self.by_id.values(),
            key=lambda s: (s.pinned, s.last)
        )

        removed = 0
        to_remove = len(self.by_id) - target
        for s in candidates:
            if removed >= to_remove:
                break
            self.by_id.pop(s.id, None)
            if self.by_src.get(s.src) == s:
                self.by_src.pop(s.src, None)
            removed += 1
        return removed

    def get(self, src: str, now: float | None = None) -> Session:
        now = time.monotonic() if now is None else now
        s = self.by_src.get(src)
        if s is None or now - s.last > self.idle:
            if len(self.by_id) >= self.max_sessions:
                self.prune(self.max_sessions - 100)
            self._n += 1
            s = Session(f"{self.prefix}-{self._n:05d}", src, now)
            self.by_src[src] = s
            self.by_id[s.id] = s
        return s
