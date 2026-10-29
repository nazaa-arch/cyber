"""Pemeta ATT&CK for ICS: tabel YAML -> ID teknik."""
from __future__ import annotations

import pathlib

import yaml

_PATH = pathlib.Path(__file__).with_name("attck_ics.yaml")


class AttckMapper:
    def __init__(self, path: pathlib.Path = _PATH):
        d = yaml.safe_load(path.read_text(encoding="utf-8"))
        self.techniques: dict = d["techniques"]
        self.actions: dict = d["actions"]
        self.flags: dict = d["flags"]

    def map(self, event: dict) -> list[str]:
        out: list[str] = list(self.actions.get(event.get("action"), []))
        for f in event.get("flags", []) or []:
            for t in self.flags.get(f, []):
                if t not in out:
                    out.append(t)
        return out

    def tactic(self, tid: str) -> str:
        return self.techniques.get(tid, {}).get("tactic", "?")

    def name(self, tid: str) -> str:
        return self.techniques.get(tid, {}).get("name", tid)
