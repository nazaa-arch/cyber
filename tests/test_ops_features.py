import sys, pathlib
sys.path.insert(0, str(pathlib.Path(__file__).resolve().parents[1]))

from console import bot as botmod
from console.bot import TelegramChannel
from console.pusat import Pusat
from evidence.session_store import SessionStore
from node import SatuanNode


def test_telegram_send_retries_until_success(monkeypatch):
    ch = TelegramChannel("123:abc", 1)
    calls = []

    def fake_send(payload):
        calls.append(1)
        return 0 if len(calls) < 3 else 77

    monkeypatch.setattr(ch, "_send_sync", fake_send)
    monkeypatch.setattr(botmod.time, "sleep", lambda s: None)
    assert ch._send_retry({"text": "x"}) == 77
    assert len(calls) == 3


def test_telegram_send_gives_up_after_attempts(monkeypatch):
    ch = TelegramChannel("123:abc", 1)
    monkeypatch.setattr(ch, "_send_sync", lambda p: 0)
    monkeypatch.setattr(botmod.time, "sleep", lambda s: None)
    assert ch._send_retry({"text": "x"}, attempts=3) == 0


def test_campaign_resolve_and_reset_lifecycle():
    p = Pusat()
    p.register_unit("A", -6.0, 106.0)
    p.register_unit("B", -7.0, 110.0)
    p.campaign_list = [{"id": "k1", "satuan": ["A", "B"], "bukti": "x",
                        "urutan_sentuh": [{"satuan": "A", "first_wall": 1.0},
                                          {"satuan": "B", "first_wall": 2.0}]}]
    p.corr.sessions[("A", "s1")] = {"satuan": "A"}
    assert p.status("A") == "Kampanye Terdeteksi"
    assert p.get_campaign_vectors()
    assert p.resolve_campaigns("k1") == ["k1"]
    assert p.status("A") == "Aman" and p.status("B") == "Aman"
    assert p.get_campaign_vectors() == []
    p.reset_incidents()
    assert p.campaign_list == [] and not p.corr.sessions and not p.resolved_campaigns


def test_persistent_store_survives_restart_with_unique_session_ids(tmp_path):
    db = str(tmp_path / "sessions.db")
    n1 = SatuanNode("U-persist", 3, ("127.0.0.1", 1), str(tmp_path), set(), db_path=db)
    n1.store.put_session({"satuan": "U-persist", "session": "persist-1", "src": "1.2.3.4",
                          "stage": "recon", "depth": 1, "diverted": False, "techniques": [],
                          "event_count": 1, "high_tier": False, "first_wall": 1.0})
    n2 = SatuanNode("U-persist", 3, ("127.0.0.1", 1), str(tmp_path), set(), db_path=db)
    assert any(s["session"] == "persist-1" for s in n2.store.sessions())
    assert "-" in n2.sessions.prefix and len(n2.sessions.prefix.split("-")) >= 2   # ada cap waktu
    mem = SatuanNode("U-mem", 3, ("127.0.0.1", 1), str(tmp_path / "m"), set())
    assert mem.sessions.prefix == "mem"                                          # mode memori tak berubah
