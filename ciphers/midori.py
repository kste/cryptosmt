'''
Created on Jan 01, 2017

@author: ralph
'''

from parser import stpcommands
from ciphers.cipher import AbstractCipher
from ciphers import components


class MidoriCipher(AbstractCipher):
    """
    Represents the differential behaviour of Midori and can be used
    to find differential characteristics for the given parameters.
    """

    @property
    def name(self):
        return "midori"

    def getFormatString(self):
        """
        Returns the print format.
        """
        return ['SB', 'SC', 'MC', 'w']

    def validate_parameters(self, parameters):
        """
        Midori supports 64-bit wordsize.
        """
        if parameters["wordsize"] != 64:
            parameters["wordsize"] = 64

    def setup_variables(self, stp_file, parameters):
        """
        Declare variables for MIDORI.
        """
        wordsize = parameters["wordsize"]
        rounds = parameters["rounds"]
        
        self.sb = self.declare_variable_vector(stp_file, "SB", rounds, wordsize, is_state=True)
        self.sc = self.declare_variable_vector_per_round(stp_file, "SC", rounds, wordsize)
        self.mc = self.declare_variable_vector_per_round(stp_file, "MC", rounds, wordsize)
        self.w = self.declare_variable_vector_per_round(stp_file, "w", rounds, wordsize, is_weight=True)

    def apply_round_constraints(self, stp_file, round_nr, parameters):
        """
        Apply MIDORI round constraints.
        """
        wordsize = parameters["wordsize"]
        sb_in = self.sb[round_nr]
        sc = self.sc[round_nr]
        mc = self.mc[round_nr]
        sb_out = self.sb[round_nr+1]
        w = self.w[round_nr]

        # Substitution Layer
        midori_sbox = [0xc, 0xa, 0xd, 3, 0xe, 0xb, 0xf, 7, 8, 9, 1, 5, 0, 2, 4, 6]
        for i in range(16):
            components.add_4bit_sbox_at_pos(stp_file, midori_sbox, i, sb_in, sc, w)

        # ShuffleCells
        permutation = [0x0, 0xa, 0x5, 0xf, 0xe, 0x4, 0xb, 0x1,
                       0x9, 0x3, 0xc, 0x6, 0x7, 0xd, 0x2, 0x8]
        # Each val is a 4-bit nibble index
        for idx, val in enumerate(permutation):
            components.add_assignment(stp_file, f"{mc}[{4*idx + 3}:{4*idx}]", f"{sc}[{4*val + 3}:{4*val}]")

        # MixColumns
        components.add_midori_mix_columns(stp_file, mc, sb_out)

    def apply_iterative_constraints(self, stp_file, parameters):
        """
        Iterative constraint for MIDORI.
        """
        rounds = parameters["rounds"]
        stpcommands.assertVariableValue(stp_file, self.sb[0], self.sb[rounds])
