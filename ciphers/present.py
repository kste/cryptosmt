'''
Created on Dec 27, 2016

@author: ralph
'''

from parser import stpcommands
from ciphers.cipher import AbstractCipher
from ciphers import components


class PresentCipher(AbstractCipher):
    """
    Represents the differential behaviour of PRESENT and can be used
    to find differential characteristics for the given parameters.
    """

    @property
    def name(self):
        return "present"

    def getFormatString(self):
        """
        Returns the print format.
        """
        return ['S', 'P', 'w']

    # Present S-box
    present_sbox = [0xc, 5, 6, 0xb, 9, 0, 0xa, 0xd, 3, 0xe, 0xf, 8, 4, 7, 1, 2]
    
    # Present Permutation bit mapping
    # bit i moves to bit P(i)
    present_permutation = [0, 16, 32, 48, 1, 17, 33, 49, 2, 18, 34, 50, 3, 19, 35, 51,
                           4, 20, 36, 52, 5, 21, 37, 53, 6, 22, 38, 54, 7, 23, 39, 55,
                           8, 24, 40, 56, 9, 25, 41, 57, 10, 26, 42, 58, 11, 27, 43, 59,
                           12, 28, 44, 60, 13, 29, 45, 61, 14, 30, 46, 62, 15, 31, 47, 63]

    def validate_parameters(self, parameters):
        """
        Enforce 64-bit wordsize for PRESENT.
        """
        if parameters["wordsize"] != 64:
            parameters["wordsize"] = 64

    def setup_variables(self, stp_file, parameters):
        """
        Declare variables for PRESENT.
        """
        wordsize = parameters["wordsize"]
        rounds = parameters["rounds"]
        
        self.s = self.declare_variable_vector(stp_file, "S", rounds, wordsize, is_state=True)
        self.p = self.declare_variable_vector_per_round(stp_file, "P", rounds, wordsize)
        self.w = self.declare_variable_vector_per_round(stp_file, "w", rounds, wordsize, is_weight=True)

    def apply_round_constraints(self, stp_file, round_nr, parameters):
        """
        Apply PRESENT round constraints.
        """
        wordsize = parameters["wordsize"]
        
        # Substitution Layer
        for i in range(16):
            inputs = [f"{self.s[round_nr]}[{4*i + 3}:{4*i + 3}]",
                      f"{self.s[round_nr]}[{4*i + 2}:{4*i + 2}]",
                      f"{self.s[round_nr]}[{4*i + 1}:{4*i + 1}]",
                      f"{self.s[round_nr]}[{4*i + 0}:{4*i + 0}]"]
            outputs = [f"{self.p[round_nr]}[{4*i + 3}:{4*i + 3}]",
                       f"{self.p[round_nr]}[{4*i + 2}:{4*i + 2}]",
                       f"{self.p[round_nr]}[{4*i + 1}:{4*i + 1}]",
                       f"{self.p[round_nr]}[{4*i + 0}:{4*i + 0}]"]
            weights = [f"{self.w[round_nr]}[{4*i + 3}:{4*i + 3}]",
                       f"{self.w[round_nr]}[{4*i + 2}:{4*i + 2}]",
                       f"{self.w[round_nr]}[{4*i + 1}:{4*i + 1}]",
                       f"{self.w[round_nr]}[{4*i + 0}:{4*i + 0}]"]
            components.add_4bit_sbox(stp_file, self.present_sbox, inputs, outputs, weights)

        # Permutation Layer
        components.add_bit_permutation(stp_file, self.p[round_nr], self.s[round_nr+1], 
                                       self.present_permutation, wordsize)

    def apply_iterative_constraints(self, stp_file, parameters):
        """
        Iterative constraint for PRESENT.
        """
        rounds = parameters["rounds"]
        stpcommands.assertVariableValue(stp_file, self.s[0], self.s[rounds])
