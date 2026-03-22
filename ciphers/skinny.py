'''
Created on Dec 18, 2016

@author: stefan

Revised by Hosein Hadipour on Jan 6, 2020
'''

from parser import stpcommands
from ciphers.cipher import AbstractCipher
from ciphers import components


class SkinnyCipher(AbstractCipher):
    """
    Represents the differential behaviour of Skinny and can be used
    to find differential characteristics for the given parameters.
    """

    @property
    def name(self):
        return "skinny"

    # Sbox lookup table
    skinny_sbox = [0xc, 0x6, 0x9, 0x0, 0x1, 0xa, 0x2, 0xb, 
                    0x3, 0x8, 0x5, 0xd, 0x4, 0xe, 0x7, 0xf]

    def getFormatString(self):
        """
        Returns the print format.
        """
        return ['x', 'y', 'z', 'w']

    def write_header(self, stp_file, parameters):
        """
        Custom header for Skinny.
        """
        blocksize = parameters["blocksize"]
        header = ("% Input File for STP\n% Skinny w={}"
                  "rounds={}\n\n\n".format(blocksize, parameters["rounds"]))
        stp_file.write(header)

    def setup_variables(self, stp_file, parameters):
        """
        Declare variables in the STP file.
        """
        blocksize = parameters["blocksize"]
        rounds = parameters["rounds"]
        
        self.sc = self.declare_variable_vector(stp_file, "x", rounds, blocksize, is_state=True)
        self.sr = self.declare_variable_vector_per_round(stp_file, "y", rounds, blocksize)
        self.mc = self.declare_variable_vector_per_round(stp_file, "z", rounds, blocksize)
        self.w = self.declare_variable_vector_per_round(stp_file, "w", rounds, blocksize, is_weight=True)

    def apply_round_constraints(self, stp_file, round_nr, parameters):
        """
        Apply Skinny round constraints using components.
        """
        blocksize = parameters["blocksize"]
        sc_in = self.sc[round_nr]
        sr = self.sr[round_nr]
        mc = self.mc[round_nr]
        sc_out = self.sc[round_nr+1]
        w = self.w[round_nr]

        # SubBytes                
        for i in range(16):
            inputs = [f"{sc_in}[{4*i + 3}:{4*i + 3}]",
                      f"{sc_in}[{4*i + 2}:{4*i + 2}]",
                      f"{sc_in}[{4*i + 1}:{4*i + 1}]",
                      f"{sc_in}[{4*i + 0}:{4*i + 0}]"]
            outputs = [f"{sr}[{4*i + 3}:{4*i + 3}]",
                       f"{sr}[{4*i + 2}:{4*i + 2}]",
                       f"{sr}[{4*i + 1}:{4*i + 1}]",
                       f"{sr}[{4*i + 0}:{4*i + 0}]"]
            weights = [f"{w}[{4*i + 3}:{4*i + 3}]",
                       f"{w}[{4*i + 2}:{4*i + 2}]",
                       f"{w}[{4*i + 1}:{4*i + 1}]",
                       f"{w}[{4*i + 0}:{4*i + 0}]"]
            components.add_4bit_sbox(stp_file, self.skinny_sbox, inputs, outputs, weights)

        # ShiftRows
        # Note: We can implement bit-permutation or keep it as manual assertions if complex
        # Skinny ShiftRows is bit-range based, so we'll use assignments.
        components.add_assignment(stp_file, f"{mc}[15:0]", f"{sr}[15:0]")
        components.add_assignment(stp_file, f"{mc}[31:20]", f"{sr}[27:16]")
        components.add_assignment(stp_file, f"{mc}[19:16]", f"{sr}[31:28]")
        components.add_assignment(stp_file, f"{mc}[39:32]", f"{sr}[47:40]")
        components.add_assignment(stp_file, f"{mc}[47:40]", f"{sr}[39:32]")
        components.add_assignment(stp_file, f"{mc}[63:60]", f"{sr}[51:48]")
        components.add_assignment(stp_file, f"{mc}[59:48]", f"{sr}[63:52]")

        # MixColumns
        components.add_assignment(stp_file, f"{sc_out}[31:16]", f"{mc}[15:0]")
        components.add_xor(stp_file, f"{sc_out}[47:32]", [f"{mc}[31:16]", f"{mc}[47:32]"])
        components.add_xor(stp_file, f"{sc_out}[63:48]", [f"{mc}[47:32]", f"{mc}[15:0]"])
        components.add_xor(stp_file, f"{sc_out}[15:0]", [f"{mc}[63:48]", f"{sc_out}[63:48]"])

    def apply_iterative_constraints(self, stp_file, parameters):
        """
        Iterative constraint for Skinny.
        """
        rounds = parameters["rounds"]
        stpcommands.assertVariableValue(stp_file, self.sc[0], self.sc[rounds])
