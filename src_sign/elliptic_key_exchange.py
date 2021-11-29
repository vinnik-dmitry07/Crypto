import os
import random

from sha256 import sha256


class GF:
    def __init__(self, m=173, l_=10, j=2, k=1):
        self.m = m
        self.f = (1 << m) + (1 << l_) + (1 << j) + (1 << k) + 1
        self.mask = (1 << m) - 1

    @staticmethod
    def add(a, b):
        return a ^ b

    def mul(self, a, b):
        p = 0
        while a and b:
            if b & 1 == 1:
                p ^= a
            b >>= 1
            carry = a >> (self.m - 1)
            a = (a << 1) & self.mask
            if carry == 1:
                a ^= self.mask & self.f
        return p

    def square(self, a):
        return self.mul(a, a)

    def pow(self, a, n):
        r = 1
        while n > 0:
            if n & 1 == 1:
                r = self.mul(a, r)
            a = self.square(a)
            n = n >> 1
        return r

    def inv(self, a):
        return self.pow(a, (1 << self.m) - 2)

    def div(self, a, b):
        return self.mul(a, self.inv(b))

    def trace(self, a):
        t = a
        for _ in range(self.m - 1):
            t = self.add(self.square(t), a)
        return t

    def half_trace(self, a):
        t = a
        for i in range((self.m - 1) // 2):
            t = self.add(self.pow(t, 4), a)
        return t

    def solve_quadratic_eq(self, u, w):
        if u == 0:
            z = self.pow(w, 1 << (self.m - 1))
            return z, 1
        if w == 0:
            return 0, 2
        v = self.mul(w, self.square(self.inv(u)))
        if self.trace(v) == 1:
            return 0, 0
        t = self.half_trace(v)
        return self.mul(t, u), 2

    def random(self, minimum=0):
        return random.randint(minimum, self.mask)


class EllipticCurve:
    """y^2 + xy = x^3 + Ax^2 + B"""
    def __init__(
            self,
            gf: GF,
            A=0,
            B=0x108576C80499DB2FC16EDDF6853BBB278F6B6FB437D9,
            n=0x800000000000000000000189B4E67606E3825BB2831,
    ):
        self.gf = gf
        self.A = A
        self.B = B
        self.n = n
        self.infinity = (0, 0)

    def on_curve(self, point):
        if point == self.infinity:
            return True
        x, y = point
        left = self.gf.add(self.gf.square(y), self.gf.mul(x, y))
        right = self.gf.add(self.gf.add(self.gf.pow(x, 3), self.gf.mul(self.A, self.gf.square(x))), self.B)
        return left == right

    def generate_point(self):
        while True:
            u = self.gf.random()
            w = self.gf.add(self.gf.add(self.gf.pow(u, 3), self.gf.mul(self.A, self.gf.square(u))), self.B)
            z, k = self.gf.solve_quadratic_eq(u, w)
            if k > 0:
                return u, z

    def negate_point(self, point):
        x, y = point
        return x, self.gf.add(x, y)

    def add_points(self, point1, point2):
        if point1 == self.infinity:
            return point2
        if point2 == self.infinity:
            return point1
        if point1 == point2:
            return self.double_point(point1)
        if point2 == self.negate_point(point1):
            return self.infinity

        x1, y1 = point1
        x2, y2 = point2
        sum_x = self.gf.add(x1, x2)
        mu = self.gf.div(self.gf.add(y1, y2), sum_x)
        x3 = self.gf.add(self.gf.add(self.gf.add(self.gf.square(mu), mu), sum_x), self.A)
        y3 = self.gf.add(self.gf.add(self.gf.mul(mu, self.gf.add(x1, x3)), x3), y1)

        return x3, y3

    def double_point(self, point):
        x, y = point
        mu = self.gf.add(x, self.gf.div(y, x))
        x2 = self.gf.add(self.gf.add(self.gf.square(mu), mu), self.A)
        y2 = self.gf.add(self.gf.square(x), self.gf.mul(self.gf.add(mu, 1), x2))
        return x2, y2

    def multiple(self, point, n):
        q = self.infinity
        while n > 0:
            if n & 1 == 1:
                q = self.add_points(q, point)
            point = self.double_point(point)
            n = n >> 1
        return q

    def base_point(self):
        while True:
            p = self.generate_point()
            r = self.multiple(p, self.n)
            if r == self.infinity:
                return p


class DigitalSignature:
    def __init__(self, ec: EllipticCurve, base_point, sig_len=512):
        self.ec = ec
        self.base_point = base_point
        self.len_n = self.ec.n.bit_length()
        self.mask = (1 << (self.len_n - 1)) - 1
        self.hash_func = lambda m: sha256(m, ret_type='int')

        if sig_len % 16 != 0 or sig_len < 2 * self.len_n:
            raise RuntimeError('Signature length should be multiple of 16 and >= 2*L(n)')
        self.sig_len = sig_len

    def gen_private_key(self):
        return self.random_int(minimum=1)

    def gen_public_key(self, private_key):
        return self.ec.multiple(self.ec.negate_point(self.base_point), private_key)

    def presignature(self):
        while True:
            e = self.random_int(minimum=1)
            x, y = self.ec.multiple(self.base_point, e)
            if x != 0:
                return e, x

    def sign(self, message, private_key):
        h = self.hash_func(message) & self.ec.gf.mask
        if h == 0:
            h = 1

        while True:
            e, f_e = self.presignature()
            r = self.ec.gf.mul(h, f_e) & self.mask
            if r == 0:
                continue
            s = (e + private_key * r) % self.ec.n
            if s != 0:
                return message, self.to_signature(r, s, self.sig_len)

    def verify(self, message, signature, Q):
        h = self.hash_func(message) & self.ec.gf.mask
        if h == 0:
            h = 1

        r, s = self.to_pair(signature, self.sig_len)
        if not (0 < r < self.ec.n) or not (0 < s < self.ec.n):
            return False

        x, y = self.ec.add_points(
            self.ec.multiple(self.base_point, s),
            self.ec.multiple(Q, r))
        r2 = self.ec.gf.mul(h, x) & self.mask
        return r == r2

    @staticmethod
    def to_signature(r, s, sig_len=512):
        ln = sig_len // 2
        return (s << ln) ^ r

    @staticmethod
    def to_pair(signature, sig_len=512):
        ln = sig_len // 2
        signature_mask = (1 << ln) - 1
        r = signature & signature_mask
        s = (signature >> ln) & signature_mask
        return r, s

    def random_int(self, minimum=1):
        return random.randint(minimum, self.mask)


if __name__ == '__main__':
    ec_ = EllipticCurve(GF())
    base_point_ = ec_.base_point()
    ds = DigitalSignature(ec_, base_point_)

    private_key_ = ds.gen_private_key()
    print(f'private key = {private_key_}')

    public_key_ = ds.gen_public_key(private_key_)
    print(f'public key = {public_key_}')

    message_ = os.urandom(16)
    print(f'message = {message_}')

    signature_ = ds.sign(message_, private_key_)[1]
    print(f'signature = {signature_}')

    assert ds.verify(message_, signature_, public_key_)
    print('signature verified')
