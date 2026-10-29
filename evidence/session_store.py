"""Penyimpan Sesi (SQLite): rekam dan putar ulang sesi (Bab 6.2)."""
from __future__ import annotations

import json
import sqlite3
import threading


class SessionStore:
    def __init__(self, path: str = ":memory:"):
        self.db = sqlite3.connect(path, check_same_thread=False)
        self.lock = threading.Lock()
        self.db.executescript("""
        CREATE TABLE IF NOT EXISTS events(
          seq INTEGER PRIMARY KEY AUTOINCREMENT, event_id TEXT, session TEXT,
          ts TEXT, body TEXT);
        CREATE INDEX IF NOT EXISTS ix_ev_session ON events(session);
        CREATE TABLE IF NOT EXISTS sessions(session TEXT PRIMARY KEY, body TEXT);
        """)

    def add_event(self, ev: dict) -> None:
        with self.lock:
            self.db.execute("INSERT INTO events(event_id,session,ts,body) VALUES(?,?,?,?)",
                            (ev["event_id"], ev["session"], ev["ts"], json.dumps(ev)))
            self.db.commit()

    def events(self, session: str) -> list[dict]:
        with self.lock:
            rows = self.db.execute(
                "SELECT body FROM events WHERE session=? ORDER BY seq", (session,)).fetchall()
        return [json.loads(r[0]) for r in rows]

    def all_events(self) -> list[dict]:
        with self.lock:
            rows = self.db.execute("SELECT body FROM events ORDER BY seq").fetchall()
        return [json.loads(r[0]) for r in rows]

    def put_session(self, summary: dict) -> None:
        with self.lock:
            self.db.execute("INSERT OR REPLACE INTO sessions VALUES(?,?)",
                            (summary["session"], json.dumps(summary)))
            self.db.commit()

    def sessions(self) -> list[dict]:
        with self.lock:
            rows = self.db.execute("SELECT body FROM sessions").fetchall()
        return [json.loads(r[0]) for r in rows]

    def replay(self, session: str) -> list[dict]:
        """Langkah penyerang berurutan, seperti rekaman layar."""
        evs = self.events(session)
        if not evs:
            return []
        t0 = evs[0].get("t_mono", 0.0)
        return [{"t": round(e.get("t_mono", t0) - t0, 3), "ts": e["ts"], "action": e["action"],
                 "target": e.get("target"), "stage": e.get("stage"), "depth": e.get("depth"),
                 "techniques": e.get("attack_technique", []),
                 "note": e.get("reason") or e.get("effect") or ""} for e in evs]
