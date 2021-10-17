import codecs

from tqdm import tqdm

MOD = 256


def KSA(key):
    """
        Key Scheduling Algorithm (from wikipedia):
        for i from 0 to 255
            S[i] := i
        end
        j := 0
        for i from 0 to 255
            j := (j + S[i] + key[i mod key_length]) mod 256
            swap values of S[i] and S[j]
        end
    """
    key_length = len(key)
    S = list(range(MOD))
    j = 0
    for i in range(MOD):
        j = (j + S[i] + key[i % key_length]) % MOD
        S[i], S[j] = S[j], S[i]

    return S


def PRGA(S):
    """
        Pseudo Random Generation Algorithm (from wikipedia):
        i := 0
        j := 0
        while GeneratingOutput:
            i := (i + 1) mod 256
            j := (j + S[i]) mod 256
            swap values of S[i] and S[j]
            K := S[(S[i] + S[j]) mod 256]
            output K
        end
    """
    i = 0
    j = 0
    while True:
        i = (i + 1) % MOD
        j = (j + S[i]) % MOD

        S[i], S[j] = S[j], S[i]
        K = S[(S[i] + S[j]) % MOD]
        yield K


def get_keystream(key):
    S = KSA(key)
    return PRGA(S)


def encrypt_logic(key, text):
    key = [ord(c) for c in key]
    keystream = get_keystream(key)

    res = []
    for c in tqdm(text):
        val = ("%02X" % (c ^ next(keystream)))  # XOR and taking hex
        res.append(val)
    return ''.join(res)


def encrypt(key, plaintext):
    plaintext = [ord(c) for c in plaintext]
    # plaintext = b'1' * 10 ** 9  # todo remove
    return encrypt_logic(key, plaintext)


def decrypt(key, ciphertext):
    ciphertext = codecs.decode(ciphertext, 'hex_codec')
    res = encrypt_logic(key, ciphertext)
    # noinspection PyUnresolvedReferences
    return codecs.decode(res, 'hex_codec').decode('utf-8')


if __name__ == '__main__':
    plaintext = 'crypto'
    print('plaintext:', plaintext)

    key = 'cybernetics'
    ciphertext = encrypt(key, plaintext)
    print('ciphertext:', ciphertext)

    decrypted = decrypt(key, ciphertext)
    print('decrypted:', decrypted)
