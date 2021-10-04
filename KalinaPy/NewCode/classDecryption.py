from NewCode.classRound import classRound
from NewCode.classTable import classTable
from NewCode.classKey import classKey


class classDecryption:
    def __init__(self, flag):
        self.flag = flag

    def func_decrypt(self, clost_text_input, key_input):
        l_k_t_c = self.func_get_c_l_k_t(clost_text_input, key_input)

        round = classRound(l_k_t_c[3], l_k_t_c[0])
        key = classKey(l_k_t_c[3], l_k_t_c[0], l_k_t_c[1], l_k_t_c[2])

        round.func_fill_matrix_round(clost_text_input)

        key.func_fill_matrix_key(key_input)
        key.func_gen_intermediate_key()

        keys = key.func_gen_subkeys()

        for i in range(key.var_t):
            t = key.var_t - 1 - i
            if t == 0:
                round.func_r_add_rkey_round(keys[t])
                if self.flag: round.func_hard_print(round.state, "func_r_add_rkey_round", t)
            if t != 0 and t != key.var_t - 1:
                round.func_xor_rkey_round(keys[t])
                if self.flag: round.func_hard_print(round.state, "func_xor_rkey_round", t)
                round.func_r_m_col_round()
                if self.flag: round.func_hard_print(round.state, "func_r_m_col_round", t)
                round.func_r_s_row_round()
                if self.flag: round.func_hard_print(round.state, "func_r_s_row_round", t)
                round.func_r_s_block_round()
                if self.flag: round.func_hard_print(round.state, "func_r_s_block_round", t)
            if t == key.var_t - 1:
                round.func_r_add_rkey_round(keys[t])
                if self.flag: round.func_hard_print(round.state, "func_r_add_rkey_round", t)
                round.func_r_m_col_round()
                if self.flag: round.func_hard_print(round.state, "func_r_m_col_round", t)
                round.func_r_s_row_round()
                if self.flag: round.func_hard_print(round.state, "func_r_s_row_round", t)
                round.func_r_s_block_round()
                if self.flag: round.func_hard_print(round.state, "func_r_s_block_round", t)
        return round.state

    def func_get_c_l_k_t(self, text, key):
        # [], []
        l = len(text) * 8
        k = len(key) * 8
        t_c = classTable.l_k_t_c[str([l, k])]
        return l, k, t_c[0], t_c[1]

