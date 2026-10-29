import sys, pathlib
sys.path.insert(0, str(pathlib.Path(__file__).resolve().parents[1]))

import yaml

from telemetry.models import DepoBBMTelemetry
from evidence.hashchain import HashChain
from kelir.scoring import SessionScorer
from engine.adaptive import AdaptiveEngine


def test_lakon_yaml_loads():
    lakon_dir = pathlib.Path(__file__).resolve().parents[1] / "lakon"
    p = lakon_dir / "depo_bbm_satuan.yaml"
    d = yaml.safe_load(p.read_text(encoding="utf-8"))
    assert d["bayangan"][0]["registers"]["pump_cmd"]["effect"] == "log_only"

    # Verifikasi ketiga lakon utama (Bab 7, 15)
    cctv = yaml.safe_load((lakon_dir / "gerbang_cctv.yaml").read_text(encoding="utf-8"))
    assert cctv["lakon"] == "gerbang_dan_cctv_satuan"
    genset = yaml.safe_load((lakon_dir / "genset_listrik.yaml").read_text(encoding="utf-8"))
    assert genset["lakon"] == "genset_dan_listrik_pangkalan"


def test_telemetry_seed_differs_and_is_bounded():
    a, b = DepoBBMTelemetry(1), DepoBBMTelemetry(2)
    ra = [a.step(h / 60) for h in range(24 * 60)]
    rb = [b.step(h / 60) for h in range(24 * 60)]
    assert ra[100] != rb[100]
    assert all(0 <= r["tank_level_l"] <= 20000 for r in ra)


def test_pressure_correlates_with_flow():
    t = DepoBBMTelemetry(7)
    rows = [t.step(h / 60) for h in range(24 * 60)]
    import numpy as np
    c = np.corrcoef([r["flow_lph"] for r in rows], [r["pump_pressure_bar"] for r in rows])[0, 1]
    assert c > 0.9


def test_hashchain_detects_tamper():
    c = HashChain()
    for i in range(3):
        c.append({"n": i})
    assert c.verify()
    c.events[1]["n"] = 99
    assert not c.verify()


def test_scorer_whitelist_and_divert():
    s = SessionScorer(whitelist={"10.0.0.5"})
    assert not s.score("10.0.0.5", modbus_funcs=[6]).divert
    d = s.score("203.0.113.77", modbus_funcs=[6], scan_targets=14, scan_window_s=9)
    assert d.divert and "tulis register" in d.reason
    assert not s.score("203.0.113.9", modbus_funcs=[3]).divert


def test_adaptive_depth_and_freeze():
    e = AdaptiveEngine()
    assert e.update("enumeration") == 2
    assert e.update("manipulation_attempt") == 3
    e.observe_consistency_probe()
    assert e.update("persistence") == 3 and e.high_tier
