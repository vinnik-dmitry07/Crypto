import secrets
import hashlib

from tqdm import tqdm

from rsa import encrypt, generate_key, decrypt_crt


def get_hash(string):
    if len(string) > 2 ** 62 - 2:
        raise IndexError('The tag is too long!')
    sha = hashlib.sha1(string)
    return sha.hexdigest()


def get_seed(length):
    return secrets.token_hex(length)


def mgf(mgf_seed, mask_len, hlen):
    if mask_len > (2 ** 32) * hlen:
        raise IndexError('The mask length is too long!')
    t = b''
    if len(mgf_seed) % 2 != 0:
        mgf_seed = '0' + mgf_seed
    seed = bytes.fromhex(mgf_seed)
    rounds = mask_len // hlen
    if mask_len % hlen == 0:
        rounds -= 1
    for i in range(rounds + 1):
        temp = seed + bytes.fromhex('%08x' % i)
        t += bytes.fromhex(get_hash(temp))
    return t[:mask_len].hex()


def oaep_encrypt(m, n, e, seed=get_seed(20), tag=b''):
    m_copy = m.encode() if isinstance(m, str) else m
    k = (len(hex(n)[2:]) // 2) + 1 if len(hex(n)[2:]) % 2 == 1 else len(hex(n)[2:]) // 2
    hlen = 20
    mlen = len(m_copy)
    if mlen > (k - 2 - 2 * hlen):
        raise IndexError('The message is too long!')
    lhash = get_hash(tag)
    if k - 2 * hlen - mlen - 2 > 0:
        ps = '00' * (k - 2 - 2 * hlen - mlen)
    else:
        ps = ''
    db = lhash + ps + '01' + m_copy.hex()
    db_mask = mgf(seed, k - hlen - 1, hlen)
    masked_db = '{:0{}x}'.format(int(db, 16) ^ int(db_mask, 16), (k - hlen - 1) * 2)
    seed_mask = mgf(masked_db, hlen, hlen)
    masked_seed = '{:0{}x}'.format(
        int(seed, 16) ^ int(seed_mask, 16), 2 * hlen)
    em = '00' + masked_seed + masked_db
    c = encrypt(int(em, 16), n, e)
    result = '{:0{}x}'.format(c, 2 * k)
    return bytes.fromhex(result)


def oaep_decrypt(c, p, q, d, tag=b''):
    c_copy = c.encode() if isinstance(c, str) else c
    hlen = 20
    n = p * q
    k = (len(hex(n)[2:]) // 2) + 1 if len(hex(n)[2:]) % 2 == 1 else len(hex(n)[2:]) // 2
    clen = len(c_copy)
    if clen != k or (k < 2 * hlen + 2):
        raise IndexError('You may input cipher with wrong length!')
    cipher = int(c_copy.hex(), 16)
    em = '{:0{}x}'.format(decrypt_crt(cipher, p, q, d), k * 2)
    lhash = get_hash(tag)
    y = em[:2]
    if y != '00':
        raise ValueError('You may get wrong decrypt result, check your index!')
    masked_seed = em[2:2 * hlen + 2]
    masked_db = em[2 * hlen + 2:]
    seed_mask = mgf(masked_db, hlen, hlen)
    seed = '{:0{}x}'.format(int(seed_mask, 16) ^
                            int(masked_seed, 16), 2 * hlen)
    db_mask = mgf(seed, k - hlen - 1, hlen)
    db = '{:0{}x}'.format(int(db_mask, 16) ^ int(
        masked_db, 16), (k - hlen - 1) * 2)
    chash = db[:2 * hlen]
    if lhash != chash:
        raise ValueError('The hash is wrong. Are you use the correct tag?')
    i = 2 * hlen
    while db[i:i + 2] == '00':
        i += 2
    if db[i:i + 2] != '01':
        raise ValueError('We do not find the end byte for the ps. Is there anything wrong?')
    i += 2
    m = db[i:]
    return bytes.fromhex(m)


if __name__ == '__main__':
    pq, pub, pri = generate_key(128)
    msg = b'0' * 10 ** 2
    for _ in tqdm(range(10 ** 7)):
        cipher = oaep_encrypt(m=msg, n=pub[0], e=pub[1])
        oaep_decrypt(cipher, p=pq[0], q=pq[1], d=pri[1])
