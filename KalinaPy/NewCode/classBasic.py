from NewCode.classTable import classTable
from functools import reduce


class classBasic:
    def __init__(self, var_c = None, var_l = None):
        self.var_c = var_c
        self.var_l = var_l
        self.const_size = 8

    def func_gen_matrix(self):
        return [[0 for t in range(self.var_c)] for i in range(self.const_size)]

    def func_fill_matrix(self, input_matrix, input_mas):
        # [[], ....], []
        iterator = 0
        for i in range(self.var_c):
            for t in range(self.const_size):
                input_matrix[t][i] = input_mas[iterator]
                iterator += 1
        return input_matrix

    def func_byte_cycle_shift_right(self, input_mas, input_int):
        # [], int
        result = [i for i in input_mas]
        for i in range(input_int):
            result.insert(0, result[len(result) - 1])
            result = result[:len(result) - 1]
        return result

    def func_byte_cycle_shift_left(self, input_mas, input_int):
        # [], int
        result = [i for i in input_mas]
        for i in range(input_int):
            result.append(result[0])
            result = result[1:]
        return result

    def func_integer_part(self, input_int):
        # int
        return int(input_int // 1)

    def func_get_column(self, input_matrix, input_int):
        # [[], ....], int
        result = []
        for i in range(self.const_size): result.append(input_matrix[i][input_int])
        return result

    def func_set_column(self, input_matrix, input_mas, input_int):
        # [[], ....], [], int
        for i in range(self.const_size):
            input_matrix[i][input_int] = input_mas[i]

    def func_get_row(self, input_matrix, input_int):
        # [[], ....], int
        return input_matrix[input_int]

    def func_mul_vector(self, input_1, input_2):
        # [], []
        return [classTable.mul_table[input_1[i]][input_2[i]] for i in range(self.const_size)]

    def func_column_to_int(self, input_mas):
        # []
        val = [input_mas[i] << (i * 8) for i in range(len(input_mas))]
        return reduce((lambda x, y: x ^ y), val)

    def func_int_to_column(self, input_int):
        # int
        val = "".join(["0" for i in range(16 - len(hex(input_int)[2:]))]) + hex(input_int)[2:]
        return [int("0x" + val[i * 2:2 + i * 2], 16) for i in range(int(len(val) / 2))][::-1]

    def func_add_rkey(self, input_1, input_2):
        # [[], ....], [[], ....]
        result = self.func_gen_matrix()
        for i in range(self.var_c):
            val_1 = self.func_column_to_int(self.func_get_column(input_1, i))
            val_2 = self.func_column_to_int(self.func_get_column(input_2, i))
            val = self.func_int_to_column((val_1 + val_2) % (2**64))
            self.func_set_column(result, val, i)
        return result

    def func_r_add_rkey(self, input_1, input_2):
        # [[], ....], [[], ....]
        result = self.func_gen_matrix()
        for i in range(self.var_c):
            val_1 = self.func_column_to_int(self.func_get_column(input_1, i))
            val_2 = self.func_column_to_int(self.func_get_column(input_2, i))
            val = self.func_int_to_column((val_1 - val_2) % (2**64))
            self.func_set_column(result, val, i)
        return result

    def func_s_block(self, input_matrix):
        # [[], ....]
        return [[classTable.p[i % 4][t] for t in input_matrix[i]] for i in range(len(input_matrix))]

    def func_r_s_block(self, input_matrix):
        # [[], ....]
        return [[classTable.rp[i % 4][t] for t in input_matrix[i]] for i in range(len(input_matrix))]

    def func_s_row(self, input_matrix):
        # [[], ....]
        result = self.func_gen_matrix()
        for i in range(self.const_size):
            shift = i * self.var_l // 512
            result[i] = self.func_byte_cycle_shift_right(input_matrix[i], shift)
        return result

    def func_r_s_row(self, input_matrix):
        # [[], ....]
        result = self.func_gen_matrix()
        for i in range(self.const_size):
            shift = i * self.var_l // 512
            result[i] = self.func_byte_cycle_shift_left(input_matrix[i], shift)
        return result

    def func_m_col(self, input_matrix):
        # [[], ....]
        result = self.func_gen_matrix()
        for i in range(self.const_size):
            for t in range(self.var_c):
                row = self.func_get_row(classTable.w, i)
                column = self.func_get_column(input_matrix, t)
                result[i][t] = reduce((lambda x, y: x ^ y), self.func_mul_vector(row, column))
        return result

    def func_r_m_col(self, input_matrix):
        # [[], ....]
        result = self.func_gen_matrix()
        for i in range(self.const_size):
            for t in range(self.var_c):
                row = self.func_get_row(classTable.rw, i)
                column = self.func_get_column(input_matrix, t)
                result[i][t] = reduce((lambda x, y: x ^ y), self.func_mul_vector(row, column))
        return result

    def func_xor_rkey(self, input_1, input_2):
        # [[], ....]. [[], ....]
        result = self.func_gen_matrix()
        for i in range(self.const_size):
            for t in range(self.var_c):
                result[i][t] = input_1[i][t] ^ input_2[i][t]
        return result

    def func_gen_const(self):
        result = self.func_gen_matrix()
        for i in range(self.const_size):
            for t in range(self.var_c):
                if (i + 8 * t) % 2 == 0: result[i][t] = 1
                else: result[i][t] = 0
        return result

    def func_shift_const(self, input_matrix, input_int):
        # [[], ....], int
        for i in range(self.var_c):
            column = self.func_column_to_int(self.func_get_column(input_matrix, i))
            self.func_set_column(input_matrix, self.func_int_to_column(column << input_int), i)
        return input_matrix

    def func_matrix_cycle_shift_right(self, input_matrix, input_int):
        # [[], ....], int
        mas = self.func_matrix_to_mas(input_matrix, self.var_c)
        mas = self.func_byte_cycle_shift_right(mas, input_int)
        result = self.func_gen_matrix()
        return self.func_fill_matrix(result, mas)

    def func_l(self, input_mas):
        # []
        return input_mas[:int(len(input_mas) / 2)]

    def func_r(self, input_mas):
        # []
        return input_mas[int(len(input_mas) / 2):]

    def func_matrix_to_mas(self, input_matrix, input_int):
        # [[], ....], int
        mas = []
        for i in range(input_int): mas = mas + self.func_get_column(input_matrix, i)
        return mas

    def func_string_to_mas(self, input_str):
        # ""
        return [int("0x" + input_str[2 * i: 2 + 2 * i], 16) for i in range(int(len(input_str) / 2))]

    def func_matrix_to_string(self, input_matrix):
        # []
        result = []
        var_const = len(input_matrix)
        var_c = len(input_matrix[0])
        for i in range(var_c):
            for t in range(var_const):
                result.append(input_matrix[t][i])
        return "".join(["".join(["0" for t in range(2 - len(hex(i)[2:]))]) + hex(i)[2:] for i in result])

    def func_hard_print(self, input_matrix, input_str, input_int):
        # [[], ....], "", int
        result_str = "state[" + str(input_int) + "]." + input_str + ":"
        print(result_str + "".join([" " for i in range(30 - len(result_str))]), self.func_matrix_to_string(input_matrix))

    def func_bit_cycle_shift_left(self, input_mas, input_int):
        # [], int
        result = ["".join(["0" for t in range(8 - len(bin(i)[2:]))]) + bin(i)[2:] for i in input_mas]
        result = [i[::-1] for i in result]
        result = "".join(result)
        for i in range(input_int):
            result = result + result[0]
            result = result[1:]
        result = [result[8 * i:8 + 8 * i][::-1] for i in range(int(len(result) / 8))]
        result = [int("0b" + i, 2) for i in result]
        return result