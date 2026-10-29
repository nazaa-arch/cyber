"""Gamelan: event bus internal yang mengalirkan kejadian antarkomponen (Bab 4)."""
from __future__ import annotations

import logging
from typing import Callable

log = logging.getLogger("wayang.gamelan")


class Gamelan:
    def __init__(self):
        self._subs: list[Callable[[dict], None]] = []

    def subscribe(self, fn: Callable[[dict], None]) -> None:
        self._subs.append(fn)

    def publish(self, event: dict) -> dict:
        for fn in list(self._subs):
            try:
                fn(event)
            except Exception:  # satu pelanggan rusak tidak boleh mematikan yang lain
                log.exception("pelanggan gamelan gagal")
        return event
