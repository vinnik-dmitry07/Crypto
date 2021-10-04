# Kalina Python

Python implementation of Ukrain Kalina cipher.

## How to use?

```python
# 1) Init needed pkg 
from NewCode.classEncryption import classEncryption
from NewCode.classDecryption import classDecryption
from NewCode.classRound import classRound
from NewCode.classBasic import classBasic
from NewCode.classKey import classKey

# 2) Init input/key value in lower char
KEY = "000102030405060708090A0B0C0D0E0F".lower()
PLAINTEXT = "101112131415161718191A1B1C1D1E1F".lower()
CLOSETEXT = "81BF1C7D779BAC20E1C9EA39B4D2AD06".lower()

# 3) Create class elements and enc/dec
basic = classBasic()
encryption = classEncryption(False)
close_text = encryption.func_encrypt(basic.func_string_to_mas(PLAINTEXT), basic.func_string_to_mas(KEY))
open_text = decryption.func_decrypt(basic.func_string_to_mas(CLOSETEXT), basic.func_string_to_mas(KEY))

# 4) Print result
print("encrypt_text     ", basic.func_matrix_to_string(close_text))
print("decrypt_text     ", basic.func_matrix_to_string(open_text))
```

## Where did i get Kalina description?

Paper name: "A New Encryption Standard of Ukraine: 
			The Kalyna Block Cipher"

Source: https://eprint.iacr.org/2015/650.pdf

Only because you so pretty, i place this file in "/Docs".
