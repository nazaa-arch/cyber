"""Unit test untuk Pohon Merkle dan Pembuktian Kriptografis RFC 6962."""
import json
import pytest
from evidence.merkle import MerkleTree, MilitaryAuditProof


def test_merkle_tree_basic():
    leaves = [b"event_1", b"event_2", b"event_3", b"event_4"]
    tree = MerkleTree(leaves)
    assert tree.root is not None
    assert len(tree.root) == 64

    # Bukti inklusi untuk event_2 (index 1)
    proof = tree.get_audit_proof(1)
    assert len(proof) == 2
    assert MerkleTree.verify_audit_proof(b"event_2", 1, proof, tree.root) is True

    # Bukti inklusi palsu harus gagal
    assert MerkleTree.verify_audit_proof(b"event_palsu", 1, proof, tree.root) is False


def test_military_audit_proof_signature():
    sovereign_key = b"tni_ad_master_secret_2026"
    proof_mgr = MilitaryAuditProof("KODAM-IV", sovereign_key)

    events = [
        {"ts": 100.0, "action": "modbus_read", "src": "10.0.0.1"},
        {"ts": 101.5, "action": "shadow_divert", "src": "185.220.101.5"},
        {"ts": 102.0, "action": "coil_write_prevented", "src": "185.220.101.5"},
    ]

    dossier = proof_mgr.generate_dossier(events)
    assert dossier["satuan"] == "KODAM-IV"
    assert dossier["total_leaves"] == 3
    assert dossier["verified"] is True
    assert proof_mgr.verify_signature(dossier["merkle_root"], dossier["signature"]) is True

    # Jika root dipalsukan, verifikasi gagal
    tampered_root = "0" * 64
    assert proof_mgr.verify_signature(tampered_root, dossier["signature"]) is False
