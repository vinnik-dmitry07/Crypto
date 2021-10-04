from NewCode.classRound import classRound
from NewCode.classTable import classTable
from NewCode.classKey import classKey


class classEncryption:
    def __init__(self, flag):
        self.flag = flag

    def func_encrypt(self, plaint_text_input, key_input):
        l_k_t_c = self.func_get_c_l_k_t(plaint_text_input, key_input)

        round = classRound(l_k_t_c[3], l_k_t_c[0])
        key = classKey(l_k_t_c[3], l_k_t_c[0], l_k_t_c[1], l_k_t_c[2])

        round.func_fill_matrix_round(plaint_text_input)

        key.func_fill_matrix_key(key_input)
        key.func_gen_intermediate_key()

        keys = key.func_gen_subkeys()

        for i in range(key.var_t):
            if i == 0:
                round.func_add_rkey_round(keys[i])
                if self.flag: round.func_hard_print(round.state, "func_add_rkey_round", i)
            if i != 0 and i != key.var_t - 1:
                round.func_s_block_round()
                if self.flag: round.func_hard_print(round.state, "func_s_block_round", i)
                round.func_s_row_round()
                if self.flag: round.func_hard_print(round.state, "func_s_row_round", i)
                round.func_m_col_round()
                if self.flag: round.func_hard_print(round.state, "func_m_col_round", i)
                round.func_xor_rkey_round(keys[i])
                if self.flag: round.func_hard_print(round.state, "func_xor_rkey_round", i)
            if i == key.var_t - 1:
                round.func_s_block_round()
                if self.flag: round.func_hard_print(round.state, "func_s_block_round", i)
                round.func_s_row_round()
                if self.flag: round.func_hard_print(round.state, "func_s_row_round", i)
                round.func_m_col_round()
                if self.flag: round.func_hard_print(round.state, "func_m_col_round", i)
                round.func_add_rkey_round(keys[i])
                if self.flag: round.func_hard_print(round.state, "func_add_rkey_round", i)
        return round.state

    def func_get_c_l_k_t(self, text, key):
        # [], []
        l = len(text) * 8
        k = len(key) * 8
        t_c = classTable.l_k_t_c[str([l, k])]
        return l, k, t_c[0], t_c[1]

