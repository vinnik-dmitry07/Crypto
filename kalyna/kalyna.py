import sys
from os import path
from key_expansion import KeyExpand



sys.path.append(path.dirname(path.dirname(path.abspath(__file__))))


class KALYNA_TYPE:
    KALYNA_128_128 = {
        "Nk": 2,  # number of columns in key
        "Nb": 2,  # number of columns in state
        "Nr": 10  # number of rounds
    }

    KALYNA_128_256 = {
        "Nk": 4,
        "Nb": 2,
        "Nr": 14
    }

    KALYNA_256_256 = {
        "Nk": 4,
        "Nb": 4,
        "Nr": 14
    }

    KALYNA_256_512 = {
        "Nk": 8,
        "Nb": 4,
        "Nr": 18
    }

    KALYNA_512_512 = {
        "Nk": 8,
        "Nb": 8,
        "Nr": 18
    }


class Kalyna:

    def __init__(self, key, kalyna_type):
        self._key = key

        self._nk = kalyna_type["Nk"]
        self._nb = kalyna_type["Nb"]
        self._nr = kalyna_type["Nr"]

        self._words = KeyExpand(self._nb, self._nk, self._nr).expansion(key)

    def encrypt(self, plaintext):
        state = plaintext.copy()

        KeyExpand.add_round_key_expand(state, self._words[0])
        for word in self._words[1:-1]:
            state = KeyExpand.encipher_round(state, self._nb)
            KeyExpand.xor_round_key_expand(state, word)

        state = KeyExpand.encipher_round(state, self._nb)
        KeyExpand.add_round_key_expand(state, self._words[-1])

        return state

    def decrypt(self, ciphertext):
        state = ciphertext.copy()

        KeyExpand.sub_round_key_expand(state, self._words[-1])
        for word in self._words[1:-1][::-1]:
            state = KeyExpand.decipher_round(state, self._nb)
            KeyExpand.xor_round_key_expand(state, word)

        state = KeyExpand.decipher_round(state, self._nb)
        KeyExpand.sub_round_key_expand(state, self._words[0])

        return state
