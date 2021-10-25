import string
import random

from src_hash.kupyna import Kupyna
from src_hash.sha256 import sha256


def random_str(size=5, chars=string.printable):
    return ''.join(random.choice(chars) for _ in range(size))


kupyna = Kupyna(256)
for hash_func in [sha256, kupyna.hash]:
    for str_len in range(6, 7):
        previous_hashes = set()
        while True:
            a_hash = hash_func(random_str(str_len))
            if a_hash not in previous_hashes:
                previous_hashes.add(a_hash)
            else:
                break
        print(hash_func, str_len, len(previous_hashes))
