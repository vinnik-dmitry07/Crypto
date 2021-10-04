from NewCode.classBasic import classBasic
from NewCode.classTable import classTable
from functools import reduce


class classRound(classBasic):
    def __init__(self, var_c = None, var_l = None):
        classBasic.__init__(self, var_c, var_l)
        self.state = self.func_gen_matrix()

    def func_s_block_round(self):
        self.state = self.func_s_block(self.state)

    def func_r_s_block_round(self):
        self.state = self.func_r_s_block(self.state)

    def func_s_row_round(self):
        self.state = self.func_s_row(self.state)

    def func_r_s_row_round(self):
        self.state = self.func_r_s_row(self.state)

    def func_fill_matrix_round(self, input_mas):
        # []
        self.state = self.func_fill_matrix(self.state, input_mas)

    def func_m_col_round(self):
        self.state = self.func_m_col(self.state)

    def func_r_m_col_round(self):
        self.state = self.func_r_m_col(self.state)

    def func_add_rkey_round(self, input_matrix):
        # [[], ....]
        self.state = self.func_add_rkey(self.state, input_matrix)

    def func_r_add_rkey_round(self, input_matrix):
        # [[], ....]
        self.state = self.func_r_add_rkey(self.state, input_matrix)

    def func_xor_rkey_round(self, input_matrix):
        # [[], ....]
        self.state = self.func_xor_rkey(self.state, input_matrix)