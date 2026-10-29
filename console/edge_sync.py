"""Edge Sync (Bab 9.6): ringkasan kecil ke pusat, store-and-forward.

Hanya ringkasan JSON terkompresi yang dikirim (bukan log mentah). Saat link
terputus, data diantre di SQLite lokal dan dikirim setelah tersambung: korelasi
tertunda, tidak hilang.
"""
from __future__ import annotations

import json
import sqlite3
import zlib
from typing import Callable


class EdgeSync:
    def __init__(self, transport: Callable[[bytes], None], path: str = ":memory:"):
        self.transport = transport
        self.db = sqlite3.connect(path, check_same_thread=False)
        self.db.execute("""CREATE TABLE IF NOT EXISTS outbox(
            session TEXT PRIMARY KEY, seq INTEGER, payload BLOB)""")
        self._seq = 0
        self.sent_bytes = 0
        self.sent_count = 0

    def enqueue(self, summary: dict) -> None:
        """Ringkasan terbaru per sesi menggantikan yang lama (hemat bandwidth)."""
        self._seq += 1
        blob = zlib.compress(json.dumps(summary, separators=(",", ":")).encode())
        self.db.execute("INSERT OR REPLACE INTO outbox VALUES(?,?,?)",
                        (summary["session"], self._seq, blob))
        self.db.commit()

    def pending(self) -> int:
        return self.db.execute("SELECT COUNT(*) FROM outbox").fetchone()[0]

    def flush(self) -> int:
        """Kirim semua antrean. Berhenti saat link putus; data tetap tersimpan."""
        rows = self.db.execute("SELECT session, seq, payload FROM outbox ORDER BY seq").fetchall()
        sent = 0
        for session, seq, blob in rows:
            try:
                self.transport(blob)
            except Exception:
                break
            cur = self.db.execute("SELECT seq FROM outbox WHERE session=?", (session,)).fetchone()
            if cur and cur[0] == seq:      # jangan hapus bila diperbarui saat mengirim
                self.db.execute("DELETE FROM outbox WHERE session=?", (session,))
            self.sent_bytes += len(blob)
            self.sent_count += 1
            sent += 1
        self.db.commit()
        return sent


def decode(blob: bytes) -> dict:
    return json.loads(zlib.decompress(blob))
