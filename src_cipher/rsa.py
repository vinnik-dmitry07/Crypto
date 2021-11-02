import secrets

from tqdm import tqdm

from prime_test import is_prime


def extended_gcd(a, b):
    if a[2] == 0:
        return b[1]
    else:
        q = b[2] // a[2]
        t1 = b[0] - q * a[0]
        t2 = b[1] - q * a[1]
        t3 = b[2] - q * a[2]
        return extended_gcd([t1, t2, t3], a)


def get_inv(num, mod):
    nums = [0, 1, num]
    mods = [1, 0, mod]
    return extended_gcd(nums, mods)


def gcd(a, b):
    return a if b == 0 else gcd(b, a % b)


def get_mi(ls):
    m = 1
    result = []
    for pair in ls:
        m *= pair[0]
    for pair in ls:
        result.append([pair[0], m // pair[0]])
    return result, m


def get_ms_inv(ls):
    result = []
    for pair in ls:
        result.append(get_inv(pair[1], pair[0]))
    return result


def crt(ls):
    """Chinese Reminder Theorem"""
    x = 0
    ms, m = get_mi(ls)
    es = get_ms_inv(ms)
    for i in range(len(ls)):
        x = (x + ms[i][1] * es[i] * ls[i][1]) % m
    return x


def generate_prime(n):
    p = int(secrets.token_hex(n), 16)
    while not is_prime(p):
        if p % 2 == 0:
            p += 1
        else:
            p += 2
    q = int(secrets.token_hex(n), 16)
    while not is_prime(q) or p == q:
        if q % 2 == 0:
            q += 1
        else:
            q += 2
    return p, q


def generate_key(lens):
    p, q = generate_prime(lens)
    n = p * q
    e = 65537
    phi = (p - 1) * (q - 1)
    d = get_inv(e, phi)
    return [p, q], [n, e], [phi, d]


def encrypt(plaintext, n, e):
    if plaintext > n - 1:
        raise IndexError('You are trying to encrypt a message with invalid length.')
    return pow(plaintext, e, n)


def decrypt_crt(ciphertext, p, q, d):
    cipher_p = ciphertext % p
    cipher_q = ciphertext % q
    d_p = d % (p - 1)
    d_q = d % (q - 1)
    x_p = pow(cipher_p, d_p, p)
    x_q = pow(cipher_q, d_q, q)
    return crt([[p, x_p], [q, x_q]])


def decrypt(ciphertext, n, d):
    return pow(ciphertext, d, n)


if __name__ == '__main__':
    pq, pub, pri = generate_key(200)
    msg = int(b'0' * 10 ** 2)
    for _ in tqdm(range(10 ** 7)):
        cipher = encrypt(msg, n=pub[0], e=pub[1])
        hex(decrypt_crt(cipher, pq[0], pq[1], pri[1]))
        # hex(decrypt(cipher, n=pq[0], d=pri[1]))
