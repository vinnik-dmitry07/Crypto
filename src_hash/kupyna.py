from boxes_and_matrix import MDS_MATRIX, S_BOXES_ENC


class Kupyna:
    def __init__(self, n_hash_bits):
        self.sboxes = S_BOXES_ENC
        self.mds_matrix = MDS_MATRIX

        self.mult_table = [[0 for _ in range(256)] for _ in range(256)]
        for x in range(256):
            for y in range(256):
                self.mult_table[x][y] = self.multiply_gf(x, y)

        self.n_hash_bits = n_hash_bits
        if 8 <= n_hash_bits <= 256:
            self.n_bytes = 512
            self.n_rounds = 10
            self.n_words = 8
        elif 256 < n_hash_bits <= 512:
            self.n_bytes = 1024
            self.n_rounds = 14
            self.n_words = 16
        else:
            raise Exception('Unsupported hash length')

    def preprocess(self, message):
        binary_message = ''.join(format(ord(x), 'b') for x in message)

        N = len(binary_message)
        k = (-97 - N) % self.n_bytes
        binary_N = ''
        for i in range(12):
            binary_N += bin((N >> i * 8) & 0xff)[2:].zfill(8)
        padded_message = binary_message + '1' + '0' * k + binary_N

        states = []
        for b in range(len(padded_message) // self.n_bytes):
            bits = padded_message[b * self.n_bytes:(b + 1) * self.n_bytes]
            states.append(int(bits, 2))
        return states

    def xor_state_value(self, state, v):
        for j in range(self.n_words):
            state[0][j] ^= (j << 4) ^ v
        return state

    def add_state_value(self, state, v):
        for j in range(self.n_words):
            word = 0
            for i in range(8):
                word += state[i][j] << i * 8
            result = word + (0x00f0f0f0f0f0f0f3 ^ ((((self.n_words - j - 1) << 4) ^ v) << 56))
            for i in range(8):
                state[i][j] = (result >> i * 8) & 0xff
        return state

    def sub_bytes(self, state):
        new_state = [[0 for _ in range(self.n_words)] for _ in range(8)]
        for i in range(8):
            for j in range(self.n_words):
                new_state[i][j] = self.sboxes[i % 4][state[i][j]]
        return new_state

    def shift_bytes(self, state):
        new_state = [[0 for _ in range(self.n_words)] for _ in range(8)]
        for i in range(7):
            for j in range(self.n_words):
                new_state[i][(j + i) % self.n_words] = state[i][j]
        for j in range(self.n_words):
            shift = 7 if self.n_bytes == 512 else 11
            new_state[7][(j + shift) % self.n_words] = state[7][j]
        return new_state

    @staticmethod
    def multiply_gf(x, y):
        r = 0
        for i in range(8):
            if (y & 0x1) == 1:
                r ^= x
            h_bit = x & 0x80
            x = x << 1
            if h_bit == 0x80:
                x ^= 0x011d
            y >>= 1
        return r

    def mix_columns(self, state):
        new_state = [[0 for _ in range(self.n_words)] for _ in range(8)]
        for col in range(self.n_words):
            for row in range(7, -1, -1):
                product = 0
                for b in range(7, -1, -1):
                    product ^= self.mult_table[state[b][col]][self.mds_matrix[row][b]]
                new_state[row][col] = product
        return new_state

    def T_xor(self, word):
        state = self.word_to_state(word)
        for v in range(self.n_rounds):
            state = self.xor_state_value(state, v)
            state = self.sub_bytes(state)
            state = self.shift_bytes(state)
            state = self.mix_columns(state)
        return self.state_to_word(state)

    def T_add(self, word):
        state = self.word_to_state(word)
        for v in range(self.n_rounds):
            state = self.add_state_value(state, v)
            state = self.sub_bytes(state)
            state = self.shift_bytes(state)
            state = self.mix_columns(state)
        return self.state_to_word(state)

    def hash(self, message):
        if self.n_bytes == 512:
            hash_value = 1 << 510
        else:
            hash_value = 1 << 1023
        input_states = self.preprocess(message)
        for input_state in input_states:
            hash_value = self.T_xor(hash_value ^ input_state) ^ self.T_add(input_state) ^ hash_value
        return format((self.T_xor(hash_value) ^ hash_value) & int('1' * self.n_hash_bits, 2), 'x')

    def word_to_state(self, word):
        state = [[0 for _ in range(self.n_words)] for _ in range(8)]
        hex_word = hex(word)[2:].zfill(self.n_bytes // 4)
        bytes = [int(hex_word[i * 2:(i + 1) * 2], 16) for i in range(len(hex_word) // 2)]
        for j in range(self.n_words):
            for i in range(8):
                state[i][j] = bytes[j * 8 + i]
        return state

    def state_to_word(self, state):
        word = 0
        for j in range(self.n_words):
            for i in range(8):
                word += state[i][j] << (self.n_words * 8 - 1 - j * 8 - i) * 8
        return word


if __name__ == '__main__':
    print(Kupyna(256).hash('Cybernetics'))
