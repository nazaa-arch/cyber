"""Sidik jari penyerang dan korelasi lintas satuan (Bab 4.1 Pilar 5, 9.6).

sim(a,b) = alpha*J(G_a,G_b) + beta*K(tau_a,tau_b) + gamma*P(a,b)
J: Jaccard berbobot IDF atas n-gram teknik; K: kemiripan distribusi jeda;
P: kemiripan jejak protokol/kredensial.
Kampanye <=> ada kelompok >= k satuan dengan sim >= theta_c dalam jendela W.
Bukti pasti: honeytoken satu satuan dipakai di satuan lain.
"""
from __future__ import annotations

import math
from collections import defaultdict

BIN_EDGES = [0.05, 0.2, 0.5, 1.0, 2.0, 5.0, 10.0]


def _collapse(seq: list[str]) -> list[str]:
    out: list[str] = []
    for a in seq:
        if not out or out[-1] != a:
            out.append(a)
    return out


def ngrams(actions: list[str], n_max: int = 3) -> list[str]:
    seq = _collapse(actions)
    out = set()
    for n in range(1, n_max + 1):
        for i in range(len(seq) - n + 1):
            out.add(">".join(seq[i:i + n]))
    return sorted(out)


def histogram(intervals: list[float]) -> list[float]:
    h = [0.0] * (len(BIN_EDGES) + 1)
    for x in intervals:
        h[sum(1 for e in BIN_EDGES if x > e)] += 1
    tot = sum(h)
    return [round(v / tot, 4) for v in h] if tot else h


def build_fingerprint(actions: list[tuple[float, str]], proto_features: set[str]) -> dict:
    ts = [t for t, _ in actions]
    iv = [b - a for a, b in zip(ts, ts[1:])]
    return {"ngrams": ngrams([a for _, a in actions]), "hist": histogram(iv),
            "proto": sorted(proto_features)}


class Correlator:
    def __init__(self, alpha=0.5, beta=0.2, gamma=0.3, theta=0.6,
                 k_satuan=3, window_s=3600.0):
        assert abs(alpha + beta + gamma - 1.0) < 1e-9
        self.alpha, self.beta, self.gamma = alpha, beta, gamma
        self.theta, self.k, self.window = theta, k_satuan, window_s
        self.sessions: dict[tuple[str, str], dict] = {}   # (satuan, session) -> ringkasan
        self.planted: dict[str, tuple[str, str]] = {}      # token -> (satuan, session)

    def add(self, summary: dict) -> None:
        key = (summary["satuan"], summary["session"])
        self.sessions[key] = summary
        for tok in summary.get("honeytokens_planted", []):
            self.planted[tok] = key

    # ---- kemiripan ----
    def _idf(self) -> dict[str, float]:
        n = len(self.sessions)
        df: dict[str, int] = defaultdict(int)
        for s in self.sessions.values():
            for g in s["fingerprint"]["ngrams"]:
                df[g] += 1
        return {g: math.log((n + 1) / (c + 1)) + 1.0 for g, c in df.items()}

    @staticmethod
    def _wjaccard(a: set, b: set, idf: dict) -> float:
        u = a | b
        if not u:
            return 0.0
        return sum(idf.get(g, 1.0) for g in a & b) / sum(idf.get(g, 1.0) for g in u)

    @staticmethod
    def _k(ha: list[float], hb: list[float]) -> float:
        return 1.0 - 0.5 * sum(abs(x - y) for x, y in zip(ha, hb))

    @staticmethod
    def _p(a: list, b: list) -> float:
        a, b = set(a), set(b)
        return len(a & b) / len(a | b) if a | b else 0.0

    def sim(self, a: dict, b: dict, idf: dict | None = None) -> float:
        idf = idf or self._idf()
        fa, fb = a["fingerprint"], b["fingerprint"]
        return (self.alpha * self._wjaccard(set(fa["ngrams"]), set(fb["ngrams"]), idf)
                + self.beta * self._k(fa["hist"], fb["hist"])
                + self.gamma * self._p(fa["proto"], fb["proto"]))

    # ---- kampanye ----
    def campaigns(self) -> list[dict]:
        keys = list(self.sessions)
        parent = {k: k for k in keys}

        def find(x):
            while parent[x] != x:
                parent[x] = parent[parent[x]]
                x = parent[x]
            return x

        def union(a, b):
            parent[find(a)] = find(b)

        evidence: dict[tuple, str] = {}
        idf = self._idf()
        for i, ka in enumerate(keys):
            for kb in keys[i + 1:]:
                a, b = self.sessions[ka], self.sessions[kb]
                if ka[0] == kb[0] or abs(a["first_wall"] - b["first_wall"]) > self.window:
                    continue
                if self.sim(a, b, idf) >= self.theta:
                    union(ka, kb)
        token_linked: set[tuple] = set()
        for k, s in self.sessions.items():
            for tok in s.get("honeytokens_used", []):
                origin = self.planted.get(tok)
                if origin and origin[0] != k[0] and origin in self.sessions:
                    union(k, origin)
                    token_linked.update({k, origin})

        groups: dict[tuple, list] = defaultdict(list)
        for k in keys:
            groups[find(k)].append(k)
        out = []
        for members in groups.values():
            sats = {m[0] for m in members}
            has_token = any(m in token_linked for m in members)
            if len(sats) >= self.k or (has_token and len(sats) >= 2):
                ms = sorted(members, key=lambda m: self.sessions[m]["first_wall"])
                order, seen = [], set()
                for m in ms:
                    if m[0] not in seen:
                        seen.add(m[0])
                        order.append({"satuan": m[0], "session": m[1],
                                      "src": self.sessions[m]["src"],
                                      "first_wall": self.sessions[m]["first_wall"]})
                out.append({
                    "id": "kmp-" + "-".join(sorted(sats))[:40],
                    "satuan": sorted(sats), "urutan_sentuh": order,
                    "bukti": "honeytoken lintas satuan" if has_token else "kemiripan sidik jari",
                    "catatan": "Urutan satuan adalah petunjuk arah serangan, bukan atribusi final.",
                })
        return out
