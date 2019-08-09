'''
Created on Mar 17, 2017

@author: ralph
'''

from parser import stpcommands
from ciphers.cipher import AbstractCipher

from parser.stpcommands import getStringLeftRotate as rotl

class LBlockCipher(AbstractCipher):
    """
    Represents the differential behaviour of LBlock and can be used
    to find differential characteristics for the given parameters.
    """

    name = "lblock"

    def getFormatString(self):
        """
        Returns the print format.
        """
        return ['X', 'Y', 'w']

    def createSTP(self, stp_filename, parameters):
        """
        Creates an STP file to find a characteristic for LBlock with
        the given parameters.
        """

        wordsize = parameters["wordsize"]
        rounds = parameters["rounds"]
        weight = parameters["sweight"]

        with open(stp_filename, 'w') as stp_file:
            header = ("% Input File for STP\n% LBlock w={}"
                      "rounds={}\n\n\n".format(wordsize,rounds))
            stp_file.write(header)

            # Setup variables
            # x = left, y = right
            x = ["X{}".format(i) for i in range(rounds + 1)]
            y = ["Y{}".format(i) for i in range(rounds + 1)]
            f_out = ["fout{}".format(i) for i in range(rounds + 1)]
            s_out = ["sout{}".format(i) for i in range(rounds + 1)]

            # w = weight
            w = ["w{}".format(i) for i in range(rounds)]

            stpcommands.setupVariables(stp_file, x, wordsize)
            stpcommands.setupVariables(stp_file, y, wordsize)
            stpcommands.setupVariables(stp_file, f_out, wordsize)
            stpcommands.setupVariables(stp_file, s_out, wordsize)
            stpcommands.setupVariables(stp_file, w, wordsize)

            stpcommands.setupWeightComputation(stp_file, weight, w, wordsize)

            for i in range(rounds):
                self.setupLBlockRound(stp_file, x[i], y[i], x[i+1], y[i+1],
                                      f_out[i], s_out[i], w[i], wordsize)

            # No all zero characteristic
            stpcommands.assertNonZero(stp_file, x+y, wordsize)

            # Iterative characteristics only
            # Input difference = Output difference
            if parameters["iterative"]:
                stpcommands.assertVariableValue(stp_file, x[0], x[rounds])
                stpcommands.assertVariableValue(stp_file, y[0], y[rounds])

            for key, value in parameters["fixedVariables"].items():
                stpcommands.assertVariableValue(stp_file, key, value)

            for char in parameters["blockedCharacteristics"]:
                stpcommands.blockCharacteristic(stp_file, char, wordsize)

            stpcommands.setupQuery(stp_file)

        return

    def setupLBlockRound(self, stp_file, x_in, y_in, x_out, y_out, f_out, s_out, w, wordsize):
        """
        Model for differential behaviour of one round LBlock
        y[i+1] = x[i]
        x[i+1] = P(S(x[i])) xor y[i] <<< 8
        """
        command = ""

        #Assert(y[i+1] = x[i])
        command += "ASSERT({} = {});\n".format(y_out, x_in)

        y_in_rot = rotl(y_in, 8, wordsize)
        command += self.F(x_in, s_out, f_out, w)

        #Assert XOR
        command += "ASSERT({} = BVXOR({}, {}));\n".format(x_out, f_out, y_in_rot)

        stp_file.write(command)
        return

    def F(self, f_in, s_out, f_out, w):
        """
        Model for the F function used in LBlock
        """
        command = ""

        # Substitution Layer
        s0 = [0xE, 9, 0xF, 0, 0xD, 4, 0xA, 0xB, 1, 2, 8, 3, 7, 6, 0xC, 5]
        s1 = [4, 0xB, 0xE, 9, 0xF, 0xD, 0, 0xA, 7, 0xC, 5, 6, 2, 8, 1, 3]
        s2 = [1, 0xE, 7, 0xC, 0xF, 0xD, 0, 6, 0xB, 5, 9, 3, 2, 4, 8, 0xA]
        s3 = [7, 6, 8, 0xB, 0, 0xF, 3, 0xE, 9, 0xA, 0xC, 0xD, 5, 2, 4, 1]
        s4 = [0xE, 5, 0xF, 0, 7, 2, 0xC, 0xD, 1, 8, 4, 9, 0xB, 0xA, 6, 3]
        s5 = [2, 0xD, 0xB, 0xC, 0xF, 0xE, 0, 9, 7, 0xA, 6, 3, 1, 8, 4, 5]
        s6 = [0xB, 9, 4, 0xE, 0, 0xF, 0xA, 0xD, 6, 0xC, 5, 7, 3, 8, 1, 2]
        s7 = [0xD, 0xA, 0xF, 0, 0xE, 4, 9, 0xB, 2, 1, 8, 3, 7, 5, 0xC, 6]

        #s0
        variables = ["{0}[{1}:{1}]".format(f_in, 3),
                     "{0}[{1}:{1}]".format(f_in, 2),
                     "{0}[{1}:{1}]".format(f_in, 1),
                     "{0}[{1}:{1}]".format(f_in, 0),
                     "{0}[{1}:{1}]".format(s_out, 3),
                     "{0}[{1}:{1}]".format(s_out, 2),
                     "{0}[{1}:{1}]".format(s_out, 1),
                     "{0}[{1}:{1}]".format(s_out, 0),
                     "{0}[{1}:{1}]".format(w, 3),
                     "{0}[{1}:{1}]".format(w, 2),
                     "{0}[{1}:{1}]".format(w, 1),
                     "{0}[{1}:{1}]".format(w, 0)]
        command += stpcommands.add4bitSbox(s0, variables)

        #s1
        variables = ["{0}[{1}:{1}]".format(f_in, 7),
                     "{0}[{1}:{1}]".format(f_in, 6),
                     "{0}[{1}:{1}]".format(f_in, 5),
                     "{0}[{1}:{1}]".format(f_in, 4),
                     "{0}[{1}:{1}]".format(s_out, 7),
                     "{0}[{1}:{1}]".format(s_out, 6),
                     "{0}[{1}:{1}]".format(s_out, 5),
                     "{0}[{1}:{1}]".format(s_out, 4),
                     "{0}[{1}:{1}]".format(w, 7),
                     "{0}[{1}:{1}]".format(w, 6),
                     "{0}[{1}:{1}]".format(w, 5),
                     "{0}[{1}:{1}]".format(w, 4)]
        command += stpcommands.add4bitSbox(s1, variables)

        #s2
        variables = ["{0}[{1}:{1}]".format(f_in, 11),
                     "{0}[{1}:{1}]".format(f_in, 10),
                     "{0}[{1}:{1}]".format(f_in, 9),
                     "{0}[{1}:{1}]".format(f_in, 8),
                     "{0}[{1}:{1}]".format(s_out, 11),
                     "{0}[{1}:{1}]".format(s_out, 10),
                     "{0}[{1}:{1}]".format(s_out, 9),
                     "{0}[{1}:{1}]".format(s_out, 8),
                     "{0}[{1}:{1}]".format(w, 11),
                     "{0}[{1}:{1}]".format(w, 10),
                     "{0}[{1}:{1}]".format(w, 9),
                     "{0}[{1}:{1}]".format(w, 8)]
        command += stpcommands.add4bitSbox(s2, variables)

        #s3
        variables = ["{0}[{1}:{1}]".format(f_in, 15),
                     "{0}[{1}:{1}]".format(f_in, 14),
                     "{0}[{1}:{1}]".format(f_in, 13),
                     "{0}[{1}:{1}]".format(f_in, 12),
                     "{0}[{1}:{1}]".format(s_out, 15),
                     "{0}[{1}:{1}]".format(s_out, 14),
                     "{0}[{1}:{1}]".format(s_out, 13),
                     "{0}[{1}:{1}]".format(s_out, 12),
                     "{0}[{1}:{1}]".format(w, 15),
                     "{0}[{1}:{1}]".format(w, 14),
                     "{0}[{1}:{1}]".format(w, 13),
                     "{0}[{1}:{1}]".format(w, 12)]
        command += stpcommands.add4bitSbox(s3, variables)

        #s4
        variables = ["{0}[{1}:{1}]".format(f_in, 19),
                     "{0}[{1}:{1}]".format(f_in, 18),
                     "{0}[{1}:{1}]".format(f_in, 17),
                     "{0}[{1}:{1}]".format(f_in, 16),
                     "{0}[{1}:{1}]".format(s_out, 19),
                     "{0}[{1}:{1}]".format(s_out, 18),
                     "{0}[{1}:{1}]".format(s_out, 17),
                     "{0}[{1}:{1}]".format(s_out, 16),
                     "{0}[{1}:{1}]".format(w, 19),
                     "{0}[{1}:{1}]".format(w, 18),
                     "{0}[{1}:{1}]".format(w, 17),
                     "{0}[{1}:{1}]".format(w, 16)]
        command += stpcommands.add4bitSbox(s4, variables)

        #s5
        variables = ["{0}[{1}:{1}]".format(f_in, 23),
                     "{0}[{1}:{1}]".format(f_in, 22),
                     "{0}[{1}:{1}]".format(f_in, 21),
                     "{0}[{1}:{1}]".format(f_in, 20),
                     "{0}[{1}:{1}]".format(s_out, 23),
                     "{0}[{1}:{1}]".format(s_out, 22),
                     "{0}[{1}:{1}]".format(s_out, 21),
                     "{0}[{1}:{1}]".format(s_out, 20),
                     "{0}[{1}:{1}]".format(w, 23),
                     "{0}[{1}:{1}]".format(w, 22),
                     "{0}[{1}:{1}]".format(w, 21),
                     "{0}[{1}:{1}]".format(w, 20)]
        command += stpcommands.add4bitSbox(s5, variables)

        #s6
        variables = ["{0}[{1}:{1}]".format(f_in, 27),
                     "{0}[{1}:{1}]".format(f_in, 26),
                     "{0}[{1}:{1}]".format(f_in, 25),
                     "{0}[{1}:{1}]".format(f_in, 24),
                     "{0}[{1}:{1}]".format(s_out, 27),
                     "{0}[{1}:{1}]".format(s_out, 26),
                     "{0}[{1}:{1}]".format(s_out, 25),
                     "{0}[{1}:{1}]".format(s_out, 24),
                     "{0}[{1}:{1}]".format(w, 27),
                     "{0}[{1}:{1}]".format(w, 26),
                     "{0}[{1}:{1}]".format(w, 25),
                     "{0}[{1}:{1}]".format(w, 24)]
        command += stpcommands.add4bitSbox(s6, variables)

        #s7
        variables = ["{0}[{1}:{1}]".format(f_in, 31),
                     "{0}[{1}:{1}]".format(f_in, 30),
                     "{0}[{1}:{1}]".format(f_in, 29),
                     "{0}[{1}:{1}]".format(f_in, 28),
                     "{0}[{1}:{1}]".format(s_out, 31),
                     "{0}[{1}:{1}]".format(s_out, 30),
                     "{0}[{1}:{1}]".format(s_out, 29),
                     "{0}[{1}:{1}]".format(s_out, 28),
                     "{0}[{1}:{1}]".format(w, 31),
                     "{0}[{1}:{1}]".format(w, 30),
                     "{0}[{1}:{1}]".format(w, 29),
                     "{0}[{1}:{1}]".format(w, 28)]
        command += stpcommands.add4bitSbox(s7, variables)

        # Permutation Layer
        command += "ASSERT({0}[7:4] = {1}[3:0]);\n".format(s_out, f_out)
        command += "ASSERT({0}[15:12] = {1}[7:4]);\n".format(s_out, f_out)
        command += "ASSERT({0}[3:0] = {1}[11:8]);\n".format(s_out, f_out)
        command += "ASSERT({0}[11:8] = {1}[15:12]);\n".format(s_out, f_out)

        command += "ASSERT({0}[23:20] = {1}[19:16]);\n".format(s_out, f_out)
        command += "ASSERT({0}[31:28] = {1}[23:20]);\n".format(s_out, f_out)
        command += "ASSERT({0}[19:16] = {1}[27:24]);\n".format(s_out, f_out)
        command += "ASSERT({0}[27:24] = {1}[31:28]);\n".format(s_out, f_out)

        return command 
