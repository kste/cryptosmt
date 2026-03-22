'''
Created on Dec 18, 2016

@author: stefan

Revised by Hosein Hadipour on Jan 6, 2020
'''

from parser import stpcommands
from ciphers.cipher import AbstractCipher


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
    # reduced product of sum (pos) representation of DDT
    skinny_sbox_rpos = "(~a1 | a0 | ~b3 | ~b2 | b1 | b0) & (~a1 | a0 | ~b3 | ~b2 | ~b1 | ~b0) & (~a2 | ~a1 | ~a0 | ~b2 | b1 | ~b0) & (~a2 | ~a1 | ~a0 | ~b2 | ~b1 | b0) & (p1 | ~p0) & (~b0 | p0) & (a1 | b2 | ~p2) & (~b2 | p0) & (~a2 | ~b2 | p2) & (~a1 | b3 | b2 | b0) & (a2 | b3 | ~p2) & (a3 | a2 | a0 | ~b3) & (~a0 | p0) & (~a1 | ~b3 | p2) & (~a3 | ~b3 | ~b1 | p2) & (~a2 | p0) & (a3 | a2 | a1 | ~b2) & (a2 | a1 | b3 | ~b1) & (a1 | b3 | b2 | b1 | ~p1) & (~a2 | b3 | ~b0 | p2) & (~a3 | a0 | b2 | ~b0 | p2) & (~a1 | b1 | b0 | p2) & (~a3 | a2 | ~b3 | p2) & (~a3 | p0) & (~a1 | ~a0 | ~b2 | p2) & (b3 | ~b2 | b1 | ~b0 | ~p2) & (~a3 | ~a2 | a1 | b1 | ~p2) & (a3 | a0 | ~b3 | b0 | p2) & (a3 | ~a1 | a0 | ~b3 | b2 | ~b0) & (~a3 | ~a0 | ~b3 | b2 | ~b0 | ~p2) & (a2 | ~a1 | a0 | ~b2 | ~p2) & (a3 | a1 | ~b3 | ~b1 | ~p2) & (~a3 | ~a2 | a0 | b2 | b0 | ~p2) & (a3 | ~a2 | ~a0 | b2 | b0 | ~p2) & (~a2 | ~a0 | b1 | b0 | p2) & (a3 | ~a2 | ~a0 | ~b0 | p2) & (~a3 | a2 | ~a0 | b2 | ~p2) & (a3 | ~a0 | b3 | ~b0 | p2) & (~a1 | b3 | ~b1 | b0 | ~p2) & (a1 | b3 | b1 | ~p2) & (~b2 | ~b1 | ~b0 | p2) & (a0 | ~b3 | b1 | ~b0 | p2)"

    def constraints_by_skinny_sbox(self, variables):
        """
        Generate constraints related to sbox
        """
        di = variables[0:4]
        do = variables[4:8]
        w = variables[9:12]
        command = self.skinny_sbox_rpos
        for i in range(4):
            command = command.replace("a%d" % (3 - i), di[i])
            command = command.replace("b%d" % (3 - i), do[i])          
            if i <= 2:
               command = command.replace("p%d" % (2 - i), w[i])
        command = "ASSERT(%s = 0bin1);\n" % command
        command += "ASSERT(%s = 0bin0);\n" % variables[8]
        return command

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
        Apply Skinny round constraints.
        """
        blocksize = parameters["blocksize"]
        self.setupSkinnyRound(stp_file, self.sc[round_nr], self.sr[round_nr], 
                              self.mc[round_nr], self.sc[round_nr+1], 
                              self.w[round_nr], blocksize)

    def apply_iterative_constraints(self, stp_file, parameters):
        """
        Iterative constraint for Skinny.
        """
        rounds = parameters["rounds"]
        stpcommands.assertVariableValue(stp_file, self.sc[0], self.sc[rounds])

    def setupSkinnyRound(self, stp_file, sc_in, sr, mc, sc_out, w, blocksize):
        """
        Model for differential behaviour of one round Skinny
        """
        command = ""
        # SubBytes                
        for i in range(16):
            variables = ["{0}[{1}:{1}]".format(sc_in, 4*i + 3),
                         "{0}[{1}:{1}]".format(sc_in, 4*i + 2),
                         "{0}[{1}:{1}]".format(sc_in, 4*i + 1),
                         "{0}[{1}:{1}]".format(sc_in, 4*i + 0),
                         "{0}[{1}:{1}]".format(sr, 4*i + 3),
                         "{0}[{1}:{1}]".format(sr, 4*i + 2),
                         "{0}[{1}:{1}]".format(sr, 4*i + 1),
                         "{0}[{1}:{1}]".format(sr, 4*i + 0),
                         "{0}[{1}:{1}]".format(w, 4*i + 3),
                         "{0}[{1}:{1}]".format(w, 4*i + 2),
                         "{0}[{1}:{1}]".format(w, 4*i + 1),
                         "{0}[{1}:{1}]".format(w, 4*i + 0)]
            command += self.constraints_by_skinny_sbox(variables)

        # ShiftRows
        command += "ASSERT({1}[15:0] = {0}[15:0]);\n".format(sr, mc)

        command += "ASSERT({1}[31:20] = {0}[27:16]);\n".format(sr, mc)
        command += "ASSERT({1}[19:16] = {0}[31:28]);\n".format(sr, mc)

        command += "ASSERT({1}[39:32] = {0}[47:40]);\n".format(sr, mc)
        command += "ASSERT({1}[47:40] = {0}[39:32]);\n".format(sr, mc)

        command += "ASSERT({1}[63:60] = {0}[51:48]);\n".format(sr, mc)
        command += "ASSERT({1}[59:48] = {0}[63:52]);\n".format(sr, mc)

        # MixColumns
        command += "ASSERT("
        command += "{0}[15:0] = {1}[31:16]".format(mc, sc_out)
        command += ");\n"

        command += "ASSERT("
        command += "BVXOR({0}[31:16], {0}[47:32]) = {1}[47:32]".format(mc, sc_out)
        command += ");\n"

        command += "ASSERT("
        command += "BVXOR({0}[47:32], {0}[15:0]) = {1}[63:48]".format(mc, sc_out)
        command += ");\n"

        command += "ASSERT("
        command += "BVXOR({0}[63:48], {1}[63:48]) = {1}[15:0]".format(mc, sc_out)
        command += ");\n"
        stp_file.write(command)
        return
