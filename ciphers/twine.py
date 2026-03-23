'''
Created on Mar 2, 2017

@author: ralph
'''

from parser import stpcommands
from ciphers.cipher import AbstractCipher
from ciphers import components

class TwineCipher(AbstractCipher):
    """
    Represents the differential behaviour of TWINE and can be used
    to find differential characteristics for the given parameters.
    """

    @property
    def name(self):
        return "twine"

    def getFormatString(self):
        """
        Returns the print format.
        """
        return ['X', 'S', 'P', 'w']

    def validate_parameters(self, parameters):
        """
        Twine is 64-bit block size.
        """
        if parameters["wordsize"] != 64:
            parameters["wordsize"] = 64

    def setup_variables(self, stp_file, parameters):
        """
        Declare variables for TWINE.
        """
        wordsize = parameters["wordsize"]
        rounds = parameters["rounds"]
        
        self.x = self.declare_variable_vector(stp_file, "X", rounds, wordsize, is_state=True)
        self.s = self.declare_variable_vector_per_round(stp_file, "S", rounds, wordsize)
        self.p = self.declare_variable_vector_per_round(stp_file, "P", rounds, wordsize)
        self.w = self.declare_variable_vector_per_round(stp_file, "w", rounds, wordsize, is_weight=True)

    def apply_round_constraints(self, stp_file, round_nr, parameters):
        """
        Apply TWINE round constraints.
        """
        wordsize = parameters["wordsize"]
        x_in = self.x[round_nr]
        s = self.s[round_nr]
        p = self.p[round_nr]
        x_out = self.x[round_nr+1]
        w = self.w[round_nr]

        # Substitution Layer
        twine_sbox = [0xC, 0, 0xF, 0xA, 2, 0xB, 9, 5, 8, 3, 0xD, 7, 1, 0xE, 6, 4]
        for i in range(8):
            # Input nibbles are 0, 2, 4, 6, 8, 10, 12, 14
            # Output nibbles in 's' are 0, 1, 2, 3, 4, 5, 6, 7
            inputs = [f"{x_in}[{4*(2*i) + 3}:{4*(2*i) + 3}]",
                      f"{x_in}[{4*(2*i) + 2}:{4*(2*i) + 2}]",
                      f"{x_in}[{4*(2*i) + 1}:{4*(2*i) + 1}]",
                      f"{x_in}[{4*(2*i) + 0}:{4*(2*i) + 0}]"]
            outputs = [f"{s}[{4*i + 3}:{4*i + 3}]",
                       f"{s}[{4*i + 2}:{4*i + 2}]",
                       f"{s}[{4*i + 1}:{4*i + 1}]",
                       f"{s}[{4*i + 0}:{4*i + 0}]"]
            weights = [f"{w}[{4*i + 3}:{4*i + 3}]",
                       f"{w}[{4*i + 2}:{4*i + 2}]",
                       f"{w}[{4*i + 1}:{4*i + 1}]",
                       f"{w}[{4*i + 0}:{4*i + 0}]"]
            components.add_4bit_sbox(stp_file, twine_sbox, inputs, outputs, weights)

        # Feistel structure
        # Even nibbles stay same: 0, 2, 4, 6, 8, 10, 12, 14
        for i in range(8):
            components.add_assignment(stp_file, f"{p}[{4*(2*i)+3}:{4*(2*i)}]", f"{x_in}[{4*(2*i)+3}:{4*(2*i)}]")
            
        # Odd nibbles XORed with Sbox output: 1, 3, 5, 7, 9, 11, 13, 15
        for i in range(8):
            components.add_xor(stp_file, f"{p}[{4*(2*i+1)+3}:{4*(2*i+1)}]", 
                               [f"{x_in}[{4*(2*i+1)+3}:{4*(2*i+1)}]", f"{s}[{4*i+3}:{4*i}]"])

        # Padding high bits of s and w
        components.add_assignment(stp_file, f"{s}[63:32]", "0x00000000")
        components.add_assignment(stp_file, f"{w}[63:32]", "0x00000000")

        # Permutation Layer
        perm = [5, 0, 1, 4, 7, 12, 3, 8, 13, 6, 9, 2, 15, 10, 11, 14]
        for i, j in enumerate(perm):
            components.add_assignment(stp_file, f"{x_out}[{4*j+3}:{4*j}]", f"{p}[{4*i+3}:{4*i}]")

    def apply_iterative_constraints(self, stp_file, parameters):
        """
        Iterative constraint for TWINE.
        """
        rounds = parameters["rounds"]
        stpcommands.assertVariableValue(stp_file, self.x[0], self.x[rounds])
