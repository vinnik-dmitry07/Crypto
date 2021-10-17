import unittest

from kalyna import Kalyna, KALYNA_TYPE
from tools import string2bytes, bytes2string


class KALYNA_TEST(unittest.TestCase):
    def test_kalyna_128_128_encryption(self):
        key = string2bytes("000102030405060708090A0B0C0D0E0F")
        input_data = string2bytes("101112131415161718191A1B1C1D1E1F")

        encrypted_input = Kalyna(key, KALYNA_TYPE.KALYNA_128_128).encrypt(input_data)

        self.assertEqual(bytes2string(encrypted_input), '81bf1c7d779bac20e1c9ea39b4d2ad06')

    def test_kalyna_128_128_decryption(self):
        key = string2bytes("000102030405060708090A0B0C0D0E0F")
        decrypted_input = Kalyna(key, KALYNA_TYPE.KALYNA_128_128).decrypt(string2bytes("81bf1c7d779bac20e1c9ea39b4d2ad06"))
        self.assertEqual(bytes2string(decrypted_input), "101112131415161718191a1b1c1d1e1f")

    def test_kalyna_128_256_encryption(self):
        key = string2bytes("000102030405060708090A0B0C0D0E0F"
                           "101112131415161718191A1B1C1D1E1F")

        input_data = string2bytes("101112131415161718191A1B1C1D1E1F")

        encrypted_input = Kalyna(key, KALYNA_TYPE.KALYNA_128_256).encrypt(input_data)

        self.assertEqual(bytes2string(encrypted_input), '658f1c0e6a8737e8aead3156b34074b3')

    def test_kalyna_128_256_decryption(self):
        key = string2bytes("000102030405060708090A0B0C0D0E0F"
                           "101112131415161718191A1B1C1D1E1F")

        decrypted_input = Kalyna(key, KALYNA_TYPE.KALYNA_128_256).decrypt(string2bytes("658f1c0e6a8737e8aead3156b34074b3"))
        self.assertEqual(bytes2string(decrypted_input), "101112131415161718191a1b1c1d1e1f")


if __name__ == '__main__':
    unittest.main()