import os
import timeit


def rot_left(x, y):
    return (x << y) % (2 ** 32 - 1)


def quarter_round(y):
    assert len(y) == 4
    z = [0] * 4
    z[1] = y[1] ^ rot_left(((y[0] + y[3]) % 2 ** 32), 7)
    z[2] = y[2] ^ rot_left(((z[1] + y[0]) % 2 ** 32), 9)
    z[3] = y[3] ^ rot_left(((z[2] + z[1]) % 2 ** 32), 13)
    z[0] = y[0] ^ rot_left(((z[3] + z[2]) % 2 ** 32), 18)
    return z


def row_round(y):
    assert len(y) == 16
    z = [0] * 16
    z[0], z[1], z[2], z[3] = quarter_round([y[0], y[1], y[2], y[3]])
    z[5], z[6], z[7], z[4] = quarter_round([y[5], y[6], y[7], y[4]])
    z[10], z[11], z[8], z[9] = quarter_round([y[10], y[11], y[8], y[9]])
    z[15], z[12], z[13], z[14] = quarter_round([y[15], y[12], y[13], y[14]])
    return z


def column_round(x):
    assert len(x) == 16
    y = [0] * 16
    y[0], y[4], y[8], y[12] = quarter_round([x[0], x[4], x[8], x[12]])
    y[5], y[9], y[13], y[1] = quarter_round([x[5], x[9], x[13], x[1]])
    y[10], y[14], y[2], y[6] = quarter_round([x[10], x[14], x[2], x[6]])
    y[15], y[3], y[7], y[11] = quarter_round([x[15], x[3], x[7], x[11]])
    return y


def double_round(x):
    return row_round(column_round(x))


def little_endian(b):
    assert len(b) == 4
    return b[0] ^ (b[1] << 8) ^ (b[2] << 16) ^ (b[3] << 24)


def little_endian_invert(w):
    return [w & 0xff, (w >> 8) & 0xff, (w >> 16) & 0xff, (w >> 24) & 0xff]


def salsa_20_hash(x):
    _x = [0] * 16
    i = 0
    k = 0
    while i < 16:
        _x[i] = little_endian(x[k:k + 4])
        k += 4
        i += 1

    z = _x
    for j in range(10):
        z = double_round(z)

    y = []
    for i in range(16):
        w = z[i] + _x[i]
        y.append(w & 0xff)
        y.append((w >> 8) & 0xff)
        y.append((w >> 16) & 0xff)
        y.append((w >> 24) & 0xff)

    return y


# 0x61707865, 0x3320646e, 0x79622d32, 0x6b206574
sig_0 = [101, 120, 112, 97]
sig_1 = [110, 100, 32, 51]
sig_2 = [50, 45, 98, 121]
sig_3 = [116, 101, 32, 107]


def crypt(text, key, nonce):
    text = b'1' * 10 ** 9  # todo remove
    assert len(nonce) == 8
    assert len(key) == 32
    _nonce = list(nonce)
    _key = list(key)
    block_counter = [0] * 8
    k0 = _key[:16]
    k1 = _key[16:]
    enc_list = [
        a ^ b for a, b in
        zip(
            salsa_20_hash(sig_0 + k0 + sig_1 + _nonce + block_counter + sig_2 + k1 + sig_3),
            list(text)
        )
    ]
    return bytearray(enc_list)


def main():
    nonce = bytearray(range(8))

    plaintext = 'crypto'
    print('plaintext:', plaintext)

    key = bytearray(os.urandom(32))
    ciphertext = crypt(text=plaintext.encode('UTF-8'), nonce=nonce, key=key)
    print('ciphertext:', ciphertext)

    decrypted = crypt(text=ciphertext, nonce=nonce, key=key) #  .decode('utf-8')
    print('decrypted:', decrypted)


if __name__ == '__main__':
    print(timeit.timeit(main, number=1))
