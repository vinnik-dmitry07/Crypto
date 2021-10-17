import numpy as np


def string2bytes(string, dtype=np.uint64):
    return np.frombuffer(bytearray.fromhex(string), dtype=dtype)


def bytes2string(bytes_array):
    return "".join(["{0:0{1}x}".format(num, 2) for num in bytearray(bytes_array)])


def to_type(num_array, dtype):
    bytes_array = bytearray(num_array)
    return np.frombuffer(bytes_array, dtype=dtype)