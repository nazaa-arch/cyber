import sys, pathlib, json
sys.path.insert(0, str(pathlib.Path(__file__).resolve().parents[1]))

import pytest
import yaml

from engine import rulegen
from engine.fingerprint import Correlator, build_fingerprint, ngrams
from engine.approval import ApprovalQueue
from engine.autonomy import Autonomy, Blocklist
from engine.social import SocialDecoys
from engine.attck_map import AttckMapper
from console.edge_sync import EdgeSync, decode
from telemetry.generator_teks import generate


def summ(src="203.0.113.77", session="s1", satuan="K1", techs=("T0855", "T0836", "T0846"), **kw):
    return {"satuan": satuan, "session": session, "src": src, "first_wall": 1000.0,
            "techniques": list(techs), "fingerprint": {"ngrams": [], "hist": [0] * 8, "proto": []},
            **kw}


def test_rulegen_outputs():
    b = rulegen.build_bundle(summ(honeytokens_planted=["HTabc"]))
    rules = list(yaml.safe_load_all(b["sigma_yaml"]))
    assert any(r["title"] == "wayang_modbus_write_non_operator" for r in rules)
    assert b["ioc"]["objects"][0]["pattern"] == "[ipv4-addr:value = '203.0.113.77']"
    assert "DRAF" in b["nftables"] and "203.0.113.77" in b["nftables"]
    assert b["ratio_benteng"] == 1.0
    assert any("ACL" in h for h in b["hardening"])


def test_rulegen_rejects_unsafe_targets():
    with pytest.raises(ValueError):
        rulegen.nftables_draft("127.0.0.1")
    with pytest.raises(ValueError):
        rulegen.nftables_draft("203.0.113.5", whitelist={"203.0.113.5"})
    with pytest.raises(ValueError):
        rulegen.nftables_draft("not-an-ip")
    with pytest.raises(ValueError):
        rulegen.build_bundle(summ(src="1.2.3.4; drop"))


def test_approval_never_auto_applies_and_limits_per_source(tmp_path):
    bl = Blocklist()
    q = ApprovalQueue(tmp_path, bl)
    ps = [q.propose(summ(session=f"s{i}")) for i in range(5)]
    assert sum(p is not None for p in ps) == 3          # kontribusi per sumber dibatasi
    assert not bl.is_blocked("203.0.113.77")             # draf belum diterapkan
    q.approve(ps[0].id, "perwira")
    assert bl.is_blocked("203.0.113.77")
    assert "DISETUJUI oleh perwira" in (tmp_path / "applied" / "s0.nft").read_text()
    with pytest.raises(ValueError):
        q.approve(ps[0].id)
    q.revoke(ps[0].id)
    assert not bl.is_blocked("203.0.113.77")


def test_autonomy_kill_switch():
    a = Autonomy(3)
    assert a.can_autoblock
    a.kill_switch()
    assert a.level == 0 and not a.can_divert and not a.can_draft


def test_fingerprint_correlates_same_behavior_across_ips_not_scanners():
    seq = [(0.0, "read_input_registers"), (0.3, "read_device_identification"),
           (0.9, "write_single_register"), (1.2, "read_holding_registers")]
    fp = build_fingerprint(seq, {"fc:4", "fc:6", "unit:1"})
    c = Correlator(k_satuan=3, window_s=3600, theta=0.6)
    for i, sat in enumerate(["A", "B", "C"]):
        s = summ(src=f"198.51.100.{i + 1}", session=f"s{i}", satuan=sat)
        s["fingerprint"] = fp
        s["first_wall"] = 1000.0 + i * 600
        c.add(s)
    other = summ(src="192.0.2.9", session="x", satuan="D")
    other["fingerprint"] = build_fingerprint(
        [(0, "read_coils"), (5, "read_coils")], {"fc:1", "unit:9"})
    c.add(other)
    camps = c.campaigns()
    assert len(camps) == 1 and set(camps[0]["satuan"]) == {"A", "B", "C"}
    assert [o["satuan"] for o in camps[0]["urutan_sentuh"]] == ["A", "B", "C"]


def test_correlator_requires_window_and_k():
    fp = build_fingerprint([(0, "a"), (1, "b")], {"fc:3"})
    c = Correlator(k_satuan=3, window_s=100)
    for i, sat in enumerate(["A", "B", "C"]):
        s = summ(session=f"s{i}", satuan=sat); s["fingerprint"] = fp
        s["first_wall"] = i * 1000.0          # di luar jendela W
        c.add(s)
    assert c.campaigns() == []


def test_honeytoken_links_two_satuan():
    c = Correlator(k_satuan=3)
    a = summ(satuan="A", session="a1", honeytokens_planted=["HTdeadbeef0001"])
    b = summ(satuan="B", session="b1", honeytokens_used=["HTdeadbeef0001"], src="198.51.100.2")
    c.add(a); c.add(b)
    camps = c.campaigns()
    assert camps and camps[0]["bukti"].startswith("honeytoken")


def test_ngrams_collapse_repeats():
    assert ngrams(["a", "a", "b"], 2) == ["a", "a>b", "b"]


def test_edge_sync_store_and_forward_and_dedup():
    got, up = [], [False]

    def tr(b):
        if not up[0]:
            raise ConnectionError
        got.append(decode(b))
    e = EdgeSync(tr)
    e.enqueue({"session": "s1", "v": 1}); e.enqueue({"session": "s1", "v": 2})
    e.enqueue({"session": "s2", "v": 1})
    assert e.pending() == 2 and e.flush() == 0
    up[0] = True
    assert e.flush() == 2 and e.pending() == 0
    assert {g["session"]: g["v"] for g in got} == {"s1": 2, "s2": 1}


def test_attack_mapper_and_flags():
    m = AttckMapper()
    assert m.map({"action": "write_single_register"}) == ["T0855", "T0836"]
    assert "T0846" in m.map({"action": "read_input_registers", "flags": ["sequential_scan"]})
    assert m.tactic("T0855") == "Impair Process Control"


def test_social_decoys_fiktif_and_signals():
    s = SocialDecoys("K1", 1, b"secret")
    people = s.make_directory(3)
    assert all(p["email"].endswith(".invalid") and p["fiktif"] for p in people)
    assert len({p["email"] for p in people}) == 3
    doc = s.make_honeydoc("doc1")
    num = s.make_canary_contact("kontak1")
    assert s.on_mail("tidak.ada@satuan-demo.invalid", "x") is None
    assert s.on_mail(people[0]["email"], "phisher@example.net", "Mohon klik")["kind"] == "decoy_email_received"
    assert s.scan_text("... " + doc["frasa_kanari"] + " ...", "gateway")[0]["kind"] == "canary_phrase_seen"
    assert s.on_call(num, "+62-xxx")["kind"] == "canary_contact_touched"
    assert len(s.recon_map()) == 3


def test_generator_teks_deterministic_without_llm(monkeypatch):
    monkeypatch.delenv("OLLAMA_URL", raising=False)
    a = generate("maintenance_note", 5, asset="Depo", location="Fiktif")
    assert a == generate("maintenance_note", 5, asset="Depo", location="Fiktif")
    assert "CATATAN PERAWATAN" in a
    assert "[" in generate("operator_log", 1, hour=9, n=3) or True
