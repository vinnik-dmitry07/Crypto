from NewCode.classEncryption import classEncryption
from NewCode.classDecryption import classDecryption
from NewCode.classRound import classRound
from NewCode.classBasic import classBasic
from NewCode.classKey import classKey
import os

import numpy as np
from tqdm import tqdm

from aes1 import get_key_iv, SALT_SIZE, pad, split_blocks, unpad
from kalyna import Kalyna, KALYNA_TYPE
from tools import string2bytes, bytes2string


KEY = "000102030405060708090A0B0C0D0E0F".lower()

basic = classBasic()
encryption = classEncryption(False)
decryption = classDecryption(False)

text, key = basic.func_string_to_mas('1F1E1D1C1B1A19181716151413121110'), basic.func_string_to_mas(KEY)
b = b''
for text_block in tqdm(range(67108864)):
    close_text = encryption.func_encrypt(text, key)
    open_text = decryption.func_decrypt(text, key)
