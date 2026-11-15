import asyncio
import json
import sys
import pathlib

sys.path.insert(0, str(pathlib.Path(__file__).resolve().parents[1]))

from console import bot as botmod
from console.bot import TelegramChannel


def _make(tmp_path, monkeypatch, token="111:AAAATOKEN"):
    monkeypatch.setattr(botmod, "_SUBS_FILE", tmp_path / "subs.json")
    botmod._SUBS.clear()
    sent = []
    ch = TelegramChannel(token, 1, on_callback=lambda d, who: "ok",
                         on_command=lambda c: "KILLED" if c == "/kill" else "STATUS")
    monkeypatch.setattr(ch, "_send_retry", lambda payload, attempts=4: sent.append(payload) or 1)

    class _T:  # jalankan thread secara sinkron agar tes deterministik
        def __init__(self, target, args=(), daemon=None): self.t, self.a = target, args
        def start(self): self.t(*self.a)
    import types
    monkeypatch.setattr(botmod, "threading", types.SimpleNamespace(Thread=_T, Lock=botmod.threading.Lock))
    return ch, sent


def _feed(ch, monkeypatch, updates):
    class _R:
        def read(self): return json.dumps({"result": updates}).encode()
    monkeypatch.setattr(botmod.urllib.request, "urlopen", lambda *a, **k: _R())
    asyncio.run(ch.poll_once())


def _msg(uid, chat, text):
    return {"update_id": uid, "message": {"text": text, "chat": {"id": chat}, "from": {"first_name": "Juri"}}}


def test_start_subscribes_any_account_and_receives_alerts(tmp_path, monkeypatch):
    ch, sent = _make(tmp_path, monkeypatch)
    _feed(ch, monkeypatch, [_msg(1, 777, "/start")])
    assert any(p["chat_id"] == 777 and "aktif" in p["text"] for p in sent)
    sent.clear()
    ch.send("ALERT", [("Setujui blokir", "approve", "p1")])
    by_chat = {p["chat_id"]: p for p in sent}
    assert set(by_chat) == {1, 777}
    assert "reply_markup" in by_chat[1]          # pemilik: ada tombol
    assert "reply_markup" not in by_chat[777]    # pelanggan: hanya lihat


def test_subscriber_cannot_kill_or_press_buttons(tmp_path, monkeypatch):
    ch, sent = _make(tmp_path, monkeypatch)
    _feed(ch, monkeypatch, [_msg(1, 777, "/kill")])
    assert all("KILLED" not in p["text"] for p in sent)
    assert any("hanya untuk perwira" in p["text"] for p in sent)
    sent.clear()
    _feed(ch, monkeypatch, [_msg(2, 1, "/kill")])  # pemilik tetap bisa
    assert any(p["text"] == "KILLED" for p in sent)


def test_stop_unsubscribes_and_persists(tmp_path, monkeypatch):
    ch, sent = _make(tmp_path, monkeypatch)
    _feed(ch, monkeypatch, [_msg(1, 777, "/start")])
    assert 777 in json.loads((tmp_path / "subs.json").read_text())[ch.token[-8:]]
    _feed(ch, monkeypatch, [_msg(2, 777, "/stop")])
    sent.clear()
    ch.send("ALERT")
    assert {p["chat_id"] for p in sent} == {1}


def test_subscriber_limit(tmp_path, monkeypatch):
    ch, sent = _make(tmp_path, monkeypatch)
    _feed(ch, monkeypatch, [_msg(i, 1000 + i, "/start") for i in range(botmod.MAX_SUBSCRIBERS + 5)])
    assert len(botmod._SUBS[ch.token]) == botmod.MAX_SUBSCRIBERS
