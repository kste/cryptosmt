'''
Created on Mar 17, 2017

@author: ralph
'''

from parser import stpcommands
from ciphers.cipher import AbstractCipher
from ciphers import components

from parser.stpcommands import getStringLeftRotate as rotl

class LBlockCipher(AbstractCipher):
    """
    Represents the differential behaviour of LBlock and can be used
    to find differential characteristics for the given parameters.
    """

    @property
    def name(self):
        return "lblock"

    def getFormatString(self):
        """
        Returns the print format.
        """
        return ['X', 'Y', 'w']

    def validate_parameters(self, parameters):
        """
        LBlock uses 32-bit wordsize for its 64-bit block size.
        """
        if parameters["wordsize"] != 32:
            parameters["wordsize"] = 32

    def setup_variables(self, stp_file, parameters):
        """
        Declare variables for LBlock.
        """
        wordsize = parameters["wordsize"]
        rounds = parameters["rounds"]
        
        self.x = self.declare_variable_vector(stp_file, "X", rounds, wordsize, is_state=True)
        self.y = self.declare_variable_vector(stp_file, "Y", rounds, wordsize, is_state=True)
        self.f_out = self.declare_variable_vector_per_round(stp_file, "fout", rounds, wordsize)
        self.s_out = self.declare_variable_vector_per_round(stp_file, "sout", rounds, wordsize)
        self.w = self.declare_variable_vector_per_round(stp_file, "w", rounds, wordsize, is_weight=True)

    def apply_round_constraints(self, stp_file, round_nr, parameters):
        """
        Apply LBlock round constraints.
        """
        wordsize = parameters["wordsize"]
        x_in = self.x[round_nr]
        y_in = self.y[round_nr]
        x_out = self.x[round_nr+1]
        y_out = self.y[round_nr+1]
        f_out = self.f_out[round_nr]
        s_out = self.s_out[round_nr]
        w = self.w[round_nr]

        # y[i+1] = x[i]
        components.add_assignment(stp_file, y_out, x_in)

        # x[i+1] = P(S(x[i])) xor y[i] <<< 8
        y_in_rot = rotl(y_in, 8, wordsize)
        
        # F function
        # Substitution Layer
        sboxes = [
            [0xE, 9, 0xF, 0, 0xD, 4, 0xA, 0xB, 1, 2, 8, 3, 7, 6, 0xC, 5],
            [4, 0xB, 0xE, 9, 0xF, 0xD, 0, 0xA, 7, 0xC, 5, 6, 2, 8, 1, 3],
            [1, 0xE, 7, 0xC, 0xF, 0xD, 0, 6, 0xB, 5, 9, 3, 2, 4, 8, 0xA],
            [7, 6, 8, 0xB, 0, 0xF, 3, 0xE, 9, 0xA, 0xC, 0xD, 5, 2, 4, 1],
            [0xE, 5, 0xF, 0, 7, 2, 0xC, 0xD, 1, 8, 4, 9, 0xB, 0xA, 6, 3],
            [2, 0xD, 0xB, 0xC, 0xF, 0xE, 0, 9, 7, 0xA, 6, 3, 1, 8, 4, 5],
            [0xB, 9, 4, 0xE, 0, 0xF, 0xA, 0xD, 6, 0xC, 5, 7, 3, 8, 1, 2],
            [0xD, 0xA, 0xF, 0, 0xE, 4, 9, 0xB, 2, 1, 8, 3, 7, 5, 0xC, 6]
        ]
        for i in range(8):
            components.add_4bit_sbox_at_pos(stp_file, sboxes[i], i, x_in, s_out, w)

        # Permutation Layer
        components.add_assignment(stp_file, f"{f_out}[7:4]", f"{s_out}[3:0]")
        components.add_assignment(stp_file, f"{f_out}[15:12]", f"{s_out}[7:4]")
        components.add_assignment(stp_file, f"{f_out}[3:0]", f"{s_out}[11:8]")
        components.add_assignment(stp_file, f"{f_out}[11:8]", f"{s_out}[15:12]")
        components.add_assignment(stp_file, f"{f_out}[23:20]", f"{s_out}[19:16]")
        components.add_assignment(stp_file, f"{f_out}[31:28]", f"{s_out}[23:20]")
        components.add_assignment(stp_file, f"{f_out}[19:16]", f"{s_out}[27:24]")
        components.add_assignment(stp_file, f"{f_out}[27:24]", f"{s_out}[31:28]")

        # Assert XOR
        components.add_xor(stp_file, x_out, [f_out, y_in_rot])

    def apply_iterative_constraints(self, stp_file, parameters):
        """
        Iterative constraint for LBlock.
        """
        rounds = parameters["rounds"]
        stpcommands.assertVariableValue(stp_file, self.x[0], self.x[rounds])
        stpcommands.assertVariableValue(stp_file, self.y[0], self.y[rounds])
