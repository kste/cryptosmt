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

    name = "skinny"

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
        # return ['SC', 'SR', 'MC', 'w']
        return ['x', 'y', 'z', 'w']

    def createSTP(self, stp_filename, parameters):
        """
        Creates an STP file to find a differnetial trail for Skinny with
        the given parameters.
        """

        blocksize = parameters["blocksize"]
        wordsize = parameters["wordsize"]
        rounds = parameters["rounds"]
        weight = parameters["sweight"]

        if blocksize != 64:
            print("Only blocksize of 64-bit supported.")
            exit(1)

        with open(stp_filename, 'w') as stp_file:
            header = ("% Input File for STP\n% Skinny w={}"
                      "rounds={}\n\n\n".format(blocksize, rounds))
            stp_file.write(header)

            # Setup variables
            # sc = ["SC{}".format(i) for i in range(rounds + 1)]
            # sr = ["SR{}".format(i) for i in range(rounds)]
            # mc = ["MC{}".format(i) for i in range(rounds)]
            sc = ["x{}".format(i) for i in range(rounds + 1)]
            sr = ["y{}".format(i) for i in range(rounds)]
            mc = ["z{}".format(i) for i in range(rounds)]

            # w = weight
            w = ["w{}".format(i) for i in range(rounds)]

            stpcommands.setupVariables(stp_file, sc, blocksize)
            stpcommands.setupVariables(stp_file, sr, blocksize)
            stpcommands.setupVariables(stp_file, mc, blocksize)
            stpcommands.setupVariables(stp_file, w, blocksize)

            stpcommands.setupWeightComputation(stp_file, weight, w, blocksize)

            for i in range(rounds):
                self.setupSkinnyRound(stp_file, sc[i], sr[i], mc[i], sc[i+1], 
                                      w[i], blocksize)

            # No all zero characteristic
            stpcommands.assertNonZero(stp_file, sc, blocksize)

            # Iterative characteristics only
            # Input difference = Output difference
            if parameters["iterative"]:
                stpcommands.assertVariableValue(stp_file, sc[0], sc[rounds])

            for key, value in parameters["fixedVariables"].items():
                stpcommands.assertVariableValue(stp_file, key, value)

            for char in parameters["blockedCharacteristics"]:
                stpcommands.blockCharacteristic(stp_file, char, blocksize)

            stpcommands.setupQuery(stp_file)

        return

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
            #command += stpcommands.add4bitSbox(self.skinny_sbox, variables)
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
