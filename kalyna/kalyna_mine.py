import os

import numpy as np
from tqdm import tqdm

from aes1 import get_key_iv, SALT_SIZE, pad, split_blocks, unpad
from kalyna import Kalyna, KALYNA_TYPE

if __name__ == "__main__":
    password = 'my secret key'
    text = b'0' * 10 ** 9
    # text = b'hello'

    text = pad(text)
    salt = os.urandom(SALT_SIZE)
    key = np.frombuffer((get_key_iv(password.encode('utf-8'), salt)[0]), dtype=np.uint64)

    res = b''
    k = Kalyna(key, KALYNA_TYPE.KALYNA_128_128)
    for text_block in tqdm(split_blocks(text)):
        encrypted_input = k.encrypt(np.frombuffer(text_block, dtype=np.uint64))
        decrypted_input = k.decrypt(encrypted_input)
        res += bytes(bytearray(decrypted_input))
    print(unpad(res))
