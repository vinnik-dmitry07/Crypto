from NewCode.classBasic import classBasic
from NewCode.classTable import classTable


class classKey(classBasic):
    def __init__(self, var_c, var_l, var_k, var_t):
        classBasic.__init__(self, var_c, var_l)
        self.var_k = var_k
        self.var_t = var_t
        self.Ka = self.func_gen_matrix()
        self.Kw = self.func_gen_matrix()
        self.Ki = self.func_gen_matrix()
        self.K = []

    def func_fill_matrix_key(self, input_mas):
        # []
        self.K = input_mas
        if self.var_k == 2 * self.var_l:
            self.Ka = self.func_fill_matrix(self.Ka, self.func_l(input_mas))
            self.Kw = self.func_fill_matrix(self.Kw, self.func_r(input_mas))
        else:
            self.Ka = self.func_fill_matrix(self.Ka, input_mas)
            self.Kw = self.func_fill_matrix(self.Kw, input_mas)

    def func_gen_intermediate_key(self):
        self.Ki[0][0] = int((self.var_l + self.var_k + 64) / 64)
        self.Ki = self.func_add_rkey(self.Ki, self.Ka)
        self.Ki = self.func_s_block(self.Ki)
        self.Ki = self.func_s_row(self.Ki)
        self.Ki = self.func_m_col(self.Ki)
        self.Ki = self.func_xor_rkey(self.Ki, self.Kw)
        self.Ki = self.func_s_block(self.Ki)
        self.Ki = self.func_s_row(self.Ki)
        self.Ki = self.func_m_col(self.Ki)
        self.Ki = self.func_add_rkey(self.Ki, self.Ka)
        self.Ki = self.func_s_block(self.Ki)
        self.Ki = self.func_s_row(self.Ki)
        self.Ki = self.func_m_col(self.Ki)

    def func_gen_subkey(self, input_matrix, i):
        # [[], ....], int
        const = self.func_gen_const()
        const = self.func_shift_const(const, int(i / 2))
        val = self.func_add_rkey(const, self.Ki)

        input_matrix = self.func_add_rkey(input_matrix, val)
        input_matrix = self.func_s_block(input_matrix)
        input_matrix = self.func_s_row(input_matrix)
        input_matrix = self.func_m_col(input_matrix)
        input_matrix = self.func_xor_rkey(input_matrix, val)
        input_matrix = self.func_s_block(input_matrix)
        input_matrix = self.func_s_row(input_matrix)
        input_matrix = self.func_m_col(input_matrix)
        input_matrix = self.func_add_rkey(input_matrix, val)
        return input_matrix

    def func_gen_subkeys(self):
        result = []
        if self.var_k == 2 * self.var_l:
            for i in range(self.var_t):
                if classTable.even_indexes_0.count(i) != 0:
                    mas = self.func_l(self.func_byte_cycle_shift_left(self.K, i * 2))
                    matrix = self.func_gen_matrix()
                    matrix = self.func_fill_matrix(matrix, mas)
                    result.append(self.func_gen_subkey(matrix, i))
                if classTable.even_indexes_2.count(i) != 0:
                    mas = self.func_r(self.func_byte_cycle_shift_left(self.K, (i // 4) * 8))
                    matrix = self.func_gen_matrix()
                    matrix = self.func_fill_matrix(matrix, mas)
                    result.append(self.func_gen_subkey(matrix, i))
                if classTable.even_indexes_3.count(i) != 0:
                    mas = self.func_bit_cycle_shift_left(self.func_matrix_to_mas(result[i - 1], self.var_c), int(self.var_l / 4) + 24)
                    matrix = self.func_gen_matrix()
                    matrix = self.func_fill_matrix(matrix, mas)
                    result.append(matrix)
        else:
            for i in range(self.var_t):
                if classTable.even_indexes.count(i) != 0:
                    mas = self.func_byte_cycle_shift_left(self.K, i * 4)
                    matrix = self.func_gen_matrix()
                    matrix = self.func_fill_matrix(matrix, mas)
                    result.append(self.func_gen_subkey(matrix, i))
                if classTable.even_indexes_3.count(i) != 0:
                    mas = self.func_bit_cycle_shift_left(self.func_matrix_to_mas(result[i - 1], self.var_c), int(self.var_l / 4) + 24)
                    matrix = self.func_gen_matrix()
                    matrix = self.func_fill_matrix(matrix, mas)
                    result.append(matrix)
        return result