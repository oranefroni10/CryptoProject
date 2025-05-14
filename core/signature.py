"""
Minimal ECDSA on secp192r1 (toy sizes).
Only sign/verify for SHA‑256 digests – hashing may use hashlib (allowed).
"""
from hashlib import sha256
from random import SystemRandom

rand = SystemRandom()

# ---------- curve parameters (secp192r1) -------------------
p = 0xfffffffffffffffffffffffffffffffeffffffffffffffff
a = 0xfffffffffffffffffffffffffffffffefffffffffffffffc
b = 0x64210519e59c80e70fa7e9ab72243049feb8deecc146b9b1
Gx = 0x188da80eb03090f67cbf20eb43a18800f4ff0afd82ff1012
Gy = 0x07192b95ffc8da78631011ed6b24cdd573f977a11e794811
n = 0xffffffffffffffffffffffff99def836146bc9b1b4d22831
G = (Gx, Gy)


def _inv_mod(k): return pow(k, p - 2, p)


def _ec_add(P, Q):
    if P == Q:  # doubling
        lmbd = (3 * P[0] * P[0] + a) * _inv_mod(2 * P[1]) % p
    else:
        lmbd = (Q[1] - P[1]) * _inv_mod(Q[0] - P[0]) % p
    x = (lmbd * lmbd - P[0] - Q[0]) % p
    y = (lmbd * (P[0] - x) - P[1]) % p
    return (x, y)


def _ec_mul(P, k):
    R = None
    for i in reversed(bin(k)[2:]):
        if R: R = _ec_add(R, R)
        if i == '1':
            R = P if R is None else _ec_add(R, P)
    return R


class ECDSA:
    def __init__(self):
        self.d = rand.randrange(1, n - 1)
        self.Q = _ec_mul(G, self.d)

    def sign(self, data: bytes) -> tuple[int, int]:
        z = int.from_bytes(sha256(data).digest(), 'big')
        while True:
            k = rand.randrange(1, n - 1)
            x1, _ = _ec_mul(G, k)
            r = x1 % n
            if r == 0: continue
            s = (_inv_mod(k) * (z + r * self.d)) % n
            if s != 0: break
        return r, s

    def verify(self, data: bytes, sig: tuple[int, int]) -> bool:
        r, s = sig
        if not (1 <= r < n and 1 <= s < n): return False
        z = int.from_bytes(sha256(data).digest(), 'big')
        w = _inv_mod(s) % n
        u1, u2 = (z * w) % n, (r * w) % n
        X = _ec_add(_ec_mul(G, u1), _ec_mul(self.Q, u2))
        return (X[0] % n) == r
