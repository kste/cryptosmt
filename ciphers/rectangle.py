'''
Created on Sep 11, 2017

@author: ralph
'''

from parser import stpcommands
from ciphers.cipher import AbstractCipher
from ciphers import components


class RectangleCipher(AbstractCipher):
    """
    Represents the differential behaviour of RECTANGLE and can be used
    to find differential characteristics for the given parameters.
    """

    @property
    def name(self):
        return "rectangle"

    def getFormatString(self):
        """
        Returns the print format.
        """
        return ['SC', 'SR', 'w']

    def setup_variables(self, stp_file, parameters):
        """
        Declare variables for RECTANGLE.
        """
        blocksize = parameters["blocksize"]
        rounds = parameters["rounds"]
        
        self.sc = self.declare_variable_vector(stp_file, "SC", rounds, blocksize, is_state=True)
        self.sr = self.declare_variable_vector_per_round(stp_file, "SR", rounds, blocksize)
        self.w = self.declare_variable_vector_per_round(stp_file, "w", rounds, blocksize, is_weight=True)

    def apply_round_constraints(self, stp_file, round_nr, parameters):
        """
        Apply RECTANGLE round constraints.
        """
        blocksize = parameters["blocksize"]
        sc_in = self.sc[round_nr]
        sr = self.sr[round_nr]
        sc_out = self.sc[round_nr+1]
        w = self.w[round_nr]

        #SubColumn
        rectangle_sbox = [0x6, 0x5, 0xC, 0xA, 0x1, 0xE, 0x7, 0x9, 0xB, 0x0, 0x3, 0xD, 0x8, 0xF, 0x4, 0x2]
        for i in range(16):
            components.add_rectangle_sbox(stp_file, rectangle_sbox, i, sc_in, sr, w)

        #ShiftRows
        # row 0 <<< 0
        components.add_assignment(stp_file, f"{sc_out}[15:0]", f"{sr}[15:0]")

        # row 1 <<< 1
        components.add_assignment(stp_file, f"{sc_out}[31:17]", f"{sr}[30:16]")
        components.add_assignment(stp_file, f"{sc_out}[16:16]", f"{sr}[31:31]")

        # row 2 <<< 12
        components.add_assignment(stp_file, f"{sc_out}[43:32]", f"{sr}[47:36]")
        components.add_assignment(stp_file, f"{sc_out}[47:44]", f"{sr}[35:32]")

        # row 3 <<< 13
        components.add_assignment(stp_file, f"{sc_out}[63:61]", f"{sr}[50:48]")
        components.add_assignment(stp_file, f"{sc_out}[60:48]", f"{sr}[63:51]")

    def apply_iterative_constraints(self, stp_file, parameters):
        """
        Iterative constraint for RECTANGLE.
        """
        rounds = parameters["rounds"]
        stpcommands.assertVariableValue(stp_file, self.sc[0], self.sc[rounds])
