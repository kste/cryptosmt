'''
Created on April 24, 2019

@author: hadipour
'''

from parser import stpcommands
from ciphers.cipher import AbstractCipher
from ciphers import components

class CraftCipher(AbstractCipher):
    """
    This class can be used to probe differential behavior of CRAFT cipher under
    sigle tweak model.
    """

    @property
    def name(self):
        return "craft"

    craft_sbox = [0xc, 0xa, 0xd, 0x3, 0xe, 0xb, 0xf,
                  0x7, 0x8, 0x9, 0x1, 0x5, 0x0, 0x2, 0x4, 0x6]
    
    PN = [0xf, 0xc, 0xd, 0xe, 0xa, 0x9, 0x8, 0xb,
          0x6, 0x5, 0x4, 0x7, 0x1, 0x2, 0x3, 0x0]

    def getFormatString(self):
        """
        Returns the print format.
        """
        return ['x', 'y', 'z', 'w']

    def validate_parameters(self, parameters):
        """
        Craft supports 64-bit wordsize (blocksize).
        """
        if parameters["wordsize"] != 64:
            parameters["wordsize"] = 64

    def setup_variables(self, stp_file, parameters):
        """
        Declare variables for CRAFT.
        """
        wordsize = parameters["wordsize"]
        rounds = parameters["rounds"]
        
        self.x = self.declare_variable_vector(stp_file, "x", rounds, wordsize, is_state=True)
        self.y = self.declare_variable_vector_per_round(stp_file, "y", rounds, wordsize)
        self.z = self.declare_variable_vector_per_round(stp_file, "z", rounds, wordsize)
        self.w = self.declare_variable_vector_per_round(stp_file, "w", rounds, wordsize, is_weight=True)

    def apply_round_constraints(self, stp_file, round_nr, parameters):
        """
        Apply CRAFT round logic.
        """
        wordsize = parameters["wordsize"]
        x_in = self.x[round_nr]
        y = self.y[round_nr]
        z = self.z[round_nr]
        x_out = self.x[round_nr+1]
        w = self.w[round_nr]

        # MixColumns
        components.add_craft_mix_columns(stp_file, x_in, y)

        # PermuteNibbles
        for i in range(16):
            components.add_assignment(stp_file, f"{z}[{4*i + 3}:{4*i}]", f"{y}[{4*self.PN[i] + 3}:{4*self.PN[i]}]")

        # Sbox layer
        for i in range(16):
            components.add_4bit_sbox_at_pos(stp_file, self.craft_sbox, i, z, x_out, w)

    def apply_iterative_constraints(self, stp_file, parameters):
        """
        Iterative constraint for CRAFT.
        """
        rounds = parameters["rounds"]
        stpcommands.assertVariableValue(stp_file, self.x[0], self.x[rounds])
