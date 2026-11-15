"""Integrasi SOC: WAYANG -> Wazuh, Suricata -> WAYANG, WAYANG -> Suricata."""
import asyncio
import json
import pathlib
import struct
import sys

sys.path.insert(0, str(pathlib.Path(__file__).resolve().parents[1]))

import pytest

from engine import rulegen
from engine.gamelan import Gamelan
from integrations.suricata_eve import EveWatcher, IdsWatchlist, parse_alert
from integrations.wazuh_export import WazuhExporter, to_wazuh_record
sys.path.insert(0, str(pathlib.Path(__file__).resolve().parent))
from test_kelir import Client, make_stack  # noqa: E402


def _eve_alert(src, sid=9799001, sev=1, sig="WAYANG-OT tulis", dst="10.10.5.20"):
    return json.dumps({"timestamp": "2026-11-15T10:00:00.000000+0700", "event_type": "alert",
                       "src_ip": src, "src_port": 51515, "dest_ip": dst, "dest_port": 502,
                       "proto": "TCP", "app_proto": "modbus",
                       "alert": {"action": "allowed", "signature_id": sid, "rev": 1,
                                 "signature": sig, "category": "Attempted Administrator",
                                 "severity": sev}})


# ---------------- WAYANG -> Wazuh ----------------

def test_wazuh_record_flat_and_srcip_top_level():
    ev = {"ts": "2026-11-15T03:00:00Z", "satuan": "Kodim-DEMO-03", "src": "10.10.5.90",
          "session": "S1", "action": "shadow_divert", "reason": "tulis dari sumber tak terdaftar",
          "score": 1.0, "attack_technique": ["T0855"], "hash": "ab" * 32,
          "signals": {"write_function": 1.0, "unlisted_source": 1.0}, "t_mono": 1.0}
    rec = to_wazuh_record(ev, "Kodim-DEMO-03")
    assert rec["integration"] == "wayang" and rec["srcip"] == "10.10.5.90"
    assert rec["wayang"]["action"] == "shadow_divert"
    assert rec["wayang"]["mitre_ics"] == ["T0855"]
    assert rec["wayang"]["hash"] == "ab" * 32
    assert "t_mono" not in rec["wayang"]


def test_wazuh_exporter_writes_json_lines_and_skips_noisy(tmp_path):
    p = tmp_path / "wz" / "wayang-alerts.json"
    exp = WazuhExporter(str(p), "Kodim-DEMO-03")
    exp({"action": "read_holding_registers", "src": "10.0.0.9"})
    exp({"action": "shadow_divert", "src": "10.0.0.9", "reason": "x" * 100_000})
    lines = p.read_text(encoding="ascii").splitlines()
    assert len(lines) == 1
    rec = json.loads(lines[0])
    assert rec["wayang"]["truncated"] is True and len(lines[0]) < 60_000
    assert exp.status()["written"] == 1


def test_wazuh_rules_xml_wellformed_and_ids_in_range():
    import xml.etree.ElementTree as ET
    raw = (pathlib.Path(__file__).resolve().parents[1] / "integrations" / "wazuh"
           / "wayang_rules.xml").read_text(encoding="utf-8")
    root = ET.fromstring(raw[raw.index("<group"):])
    ids = [int(r.get("id")) for r in root.iter("rule")]
    assert len(ids) == len(set(ids)) and all(100700 <= i <= 100719 for i in ids)


# ---------------- Suricata -> WAYANG ----------------

def test_parse_alert_filters_severity_and_non_alerts():
    assert parse_alert(_eve_alert("10.10.5.90"))["ip"] == "10.10.5.90"
    assert parse_alert(_eve_alert("10.10.5.90", sev=3)) is None          # di bawah ambang
    assert parse_alert(json.dumps({"event_type": "flow", "src_ip": "1.2.3.4"})) is None
    assert parse_alert("{bukan json") is None
    assert parse_alert(_eve_alert("bukan-ip")) is None


def test_watchlist_ttl_and_escalation():
    now = [0.0]
    wl = IdsWatchlist(ttl_s=10, clock=lambda: now[0])
    h, new = wl.add("10.0.0.9", 1, "a", 2)
    assert new and wl.flagged("10.0.0.9") is h
    _, worse = wl.add("10.0.0.9", 1, "a", 2)
    assert not worse                                   # alert sama: tidak dianggap memburuk
    _, worse = wl.add("10.0.0.9", 2, "b", 1)
    assert worse and h.severity == 1 and h.signature == "b"
    now[0] = 11.0
    assert wl.flagged("10.0.0.9") is None


def test_eve_watcher_tails_new_lines_handles_partial_and_truncate(tmp_path):
    eve = tmp_path / "eve.json"
    eve.write_text(_eve_alert("10.0.0.1") + "\n", encoding="utf-8")     # riwayat lama
    flagged = []
    w = EveWatcher(str(eve), IdsWatchlist(), on_flag=lambda h, a: flagged.append(h.ip))
    assert w.poll() == 0                               # mulai dari ujung berkas
    with open(eve, "a", encoding="utf-8") as f:
        f.write(_eve_alert("10.0.0.2") + "\n" + _eve_alert("10.0.0.3")[:40])   # baris terpotong
    assert w.poll() == 1 and flagged == ["10.0.0.2"]
    with open(eve, "a", encoding="utf-8") as f:
        f.write(_eve_alert("10.0.0.3")[40:] + "\n")
    assert w.poll() == 1 and flagged == ["10.0.0.2", "10.0.0.3"]
    eve.write_text(_eve_alert("10.0.0.4") + "\n", encoding="utf-8")     # rotasi/potong
    w.poll()
    assert "10.0.0.4" in flagged


def test_eve_watcher_ignore_list(tmp_path):
    eve = tmp_path / "eve.json"
    eve.write_text("", encoding="utf-8")
    wl = IdsWatchlist(ignore={"10.0.0.250"})
    w = EveWatcher(str(eve), wl, from_start=True)
    eve.write_text(_eve_alert("10.0.0.250") + "\n", encoding="utf-8")
    w.poll()
    assert wl.flagged("10.0.0.250") is None


def _run(coro):
    return asyncio.run(coro)


def test_kelir_diverts_ids_flagged_unlisted_source_even_without_zero_trust():
    async def go():
        real, k, shadow, events, kport, servers = await make_stack(whitelist=("127.0.0.2",))
        k.zero_trust = False
        k.ids = IdsWatchlist()
        k.ids.add("127.0.0.1", 9799001, "WAYANG-OT tulis", 1)
        async with Client("127.0.0.1", kport) as c:
            await c.read(3, 0, 2)                       # baca biasa pun langsung ke bayangan
        div = [e for e in events if e["action"] == "shadow_divert"]
        assert div and "Suricata" in div[0]["reason"]
        assert k.stats["forwarded_unlisted_reads"] == 0
        for s in servers:
            s.close()
    _run(go())


def test_kelir_unflagged_unlisted_read_still_forwarded_without_zero_trust():
    async def go():
        real, k, shadow, events, kport, servers = await make_stack(whitelist=("127.0.0.2",))
        k.zero_trust = False
        k.ids = IdsWatchlist()
        async with Client("127.0.0.1", kport) as c:
            await c.read(3, 0, 2)
        assert not [e for e in events if e["action"] == "shadow_divert"]
        for s in servers:
            s.close()
    _run(go())


def test_kelir_flagged_operator_alert_mode_keeps_real_path():
    async def go():
        real, k, shadow, events, kport, servers = await make_stack(whitelist=("127.0.0.1",))
        k.ids = IdsWatchlist()
        k.ids.add("127.0.0.1", 2001, "ET MALWARE beacon", 1)
        async with Client("127.0.0.1", kport) as c:
            await c.read(3, 0, 2)
            await c.read(3, 0, 2)
        flags = [e for e in events if e["action"] == "ids_flag_operator"]
        assert len(flags) == 1 and flags[0]["ids_mode"] == "alert"   # satu kali per sesi
        assert not [e for e in events if e["action"] == "shadow_divert"]
        assert k.stats["forwarded_operator"] >= 2 or k.stats["forwarded"] >= 2
        for s in servers:
            s.close()
    _run(go())


def test_kelir_flagged_operator_divert_mode_quarantines():
    async def go():
        real, k, shadow, events, kport, servers = await make_stack(whitelist=("127.0.0.1",))
        k.ids = IdsWatchlist()
        k.ids_operator_mode = "divert"
        k.ids.add("127.0.0.1", 2001, "ET MALWARE beacon", 1)
        async with Client("127.0.0.1", kport) as c:
            await c.write_reg(11, 0xDEAD)
        assert [e for e in events if e["action"] == "shadow_divert"]
        assert real.writes == []                        # PLC asli tidak menerima tulis
        for s in servers:
            s.close()
    _run(go())


def test_kelir_rejects_bad_ids_mode():
    from kelir.proxy import Kelir
    with pytest.raises(ValueError):
        Kelir("X", ("127.0.0.1", 1), None, None, None, Gamelan(), ids_operator_mode="hapus")


def test_pipeline_alerts_on_ids_flag_event():
    from engine.approval import ApprovalQueue
    from engine.attck_map import AttckMapper
    from engine.autonomy import Autonomy, Blocklist
    from engine.pipeline import Pipeline
    from evidence.hashchain import HashChain
    from evidence.session_store import SessionStore
    from kelir.session import SessionRegistry
    import tempfile
    p = Pipeline("Kodim-DEMO-03", SessionRegistry(), SessionStore(":memory:"), HashChain(),
                 AttckMapper(), Autonomy(2),
                 ApprovalQueue(pathlib.Path(tempfile.mkdtemp()), Blocklist(), set()))
    p.on_event({"action": "ids_flag", "src": "10.10.5.90", "session": None, "t_mono": 1.0,
                "ts": "2026-11-15T03:00:00Z",
                "ids_signature": "WAYANG-OT tulis", "ids_sid": 9799001, "ids_severity": 1})
    assert p.alerts and p.alerts[-1]["kind"] == "ids" and p.alerts[-1]["warn"]
    assert p.verify_chain()


# ---------------- WAYANG -> Suricata ----------------

SUMMARY = {"satuan": "Kodim-DEMO-03", "session": "S-0001", "src": "10.10.5.90",
           "techniques": ["T0855", "T0888"]}


def test_suricata_rules_shape_and_deterministic_sids():
    r1 = rulegen.suricata_rules(SUMMARY)
    r2 = rulegen.suricata_rules(SUMMARY)
    assert r1 == r2
    rules = [l for l in r1.splitlines() if l and not l.startswith("#")]
    assert len(rules) == 3                                   # tulis, koneksi, device-id
    assert all(l.startswith("alert ") and l.endswith(";)") for l in rules)
    sids = [int(l.split("sid:")[1].split(";")[0]) for l in rules]
    assert len(set(sids)) == 3 and all(9_700_000 <= s < 9_800_000 for s in sids)
    assert "modbus: access write" in rules[0]
    assert "drop " in rulegen.suricata_rules(SUMMARY, action="drop")


def test_suricata_rules_refuse_unsafe_input():
    with pytest.raises(ValueError):
        rulegen.suricata_rules({**SUMMARY, "satuan": 'x"; sid:1;'})
    with pytest.raises(ValueError):
        rulegen.suricata_rules({**SUMMARY, "src": "127.0.0.1"})
    with pytest.raises(ValueError):
        rulegen.suricata_rules(SUMMARY, whitelist={"10.10.5.90"})
    with pytest.raises(ValueError):
        rulegen.suricata_rules(SUMMARY, action="reject")


def test_bundle_includes_suricata():
    b = rulegen.build_bundle(SUMMARY)
    assert "modbus: access write" in b["suricata"]


# ---------------- pcap lab ----------------

def test_lab_pcap_is_valid(tmp_path):
    from integrations.lab import make_pcap
    out = tmp_path / "x.pcap"
    make_pcap.write_pcap(str(out), make_pcap.build())
    data = out.read_bytes()
    assert struct.unpack("<I", data[:4])[0] == 0xA1B2C3D4
    assert b"\xde\xad" in data
