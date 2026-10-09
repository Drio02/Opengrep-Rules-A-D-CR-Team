import random
import secrets
from hashlib import sha256

from Crypto.Util.number import bytes_to_long, inverse, long_to_bytes


def H(x):
    if type(x) == int:
        x = long_to_bytes(x)
    return bytes_to_long(sha256(x).digest())


class DSAKey:
    def sign(self, msg):
        # ruleid: py-crypto-dsa-static-nonce
        k = H(self.y)
        r = pow(self.g, k, self.p) % self.q
        s = inverse(k, self.q) * (H(msg) + r * self.x) % self.q
        return r, s

    def sign_fixed(self, msg):
        # ok: py-crypto-dsa-static-nonce
        k = secrets.randbelow(self.q - 1) + 1
        r = pow(self.g, k, self.p) % self.q
        s = inverse(k, self.q) * (H(msg) + r * self.x) % self.q
        return r, s


class DSAPubKey:
    def verify(self, msg, signature):
        r, s = signature
        # ruleid: py-crypto-dsa-verify-no-range-check
        w = inverse(s, self.q)
        u1 = H(msg) * w % self.q
        u2 = r * w % self.q
        v = (pow(self.g, u1, self.p) * pow(self.y, u2, self.p) % self.p) % self.q
        return v == r

    def verify_fixed(self, msg, signature):
        r, s = signature
        if not (0 < r < self.q and 0 < s < self.q):
            return False
        # ok: py-crypto-dsa-verify-no-range-check
        w = inverse(s, self.q)
        u1 = H(msg) * w % self.q
        u2 = r * w % self.q
        v = (pow(self.g, u1, self.p) * pow(self.y, u2, self.p) % self.p) % self.q
        return v == r


def gen_reset_code():
    # ruleid: py-crypto-random-for-security
    return random.randint(100000, 999999)


def navbar():
    # ok: py-crypto-random-for-security
    if random.randint(0, 5) == 0:
        return "inspire"
    # ok: py-crypto-random-for-security
    return random.choice(quotes)
