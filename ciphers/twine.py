'''
Created on Mar 2, 2017

@author: ralph
'''

from parser import stpcommands
from ciphers.cipher import AbstractCipher

class TwineCipher(AbstractCipher):
    """
    Represents the differential behaviour of TWINE and can be used
    to find differential characteristics for the given parameters.
    """

    name = "twine"

    def getFormatString(self):
        """
        Returns the print format.
        """
        return ['X', 'S', 'P', 'w']

    def createSTP(self, stp_filename, parameters):
        """
        Creates an STP file to find a characteristic for TWINE with
        the given parameters.
        """

        wordsize = parameters["wordsize"]
        rounds = parameters["rounds"]
        weight = parameters["sweight"]

        with open(stp_filename, 'w') as stp_file:
            header = ("% Input File for STP\n% TWINE w={}"
                      "rounds={}\n\n\n".format(wordsize,rounds))
            stp_file.write(header)

            # Setup variables
            # x = input, s = S-Box layer output, p = permutation layer input
            x = ["X{}".format(i) for i in range(rounds + 1)]
            s = ["S{}".format(i) for i in range(rounds)]
            p = ["P{}".format(i) for i in range(rounds)]

            # w = weight
            w = ["w{}".format(i) for i in range(rounds)]

            stpcommands.setupVariables(stp_file, x, wordsize)
            stpcommands.setupVariables(stp_file, s, wordsize)
            stpcommands.setupVariables(stp_file, p, wordsize)
            stpcommands.setupVariables(stp_file, w, wordsize)

            stpcommands.setupWeightComputation(stp_file, weight, w, wordsize)

            for i in range(rounds):
                self.setupTwineRound(stp_file, x[i], s[i], p[i], x[i+1], 
                                     w[i], wordsize)

            # No all zero characteristic
            stpcommands.assertNonZero(stp_file, x, wordsize)

            # Iterative characteristics only
            # Input difference = Output difference
            if parameters["iterative"]:
                stpcommands.assertVariableValue(stp_file, x[0], x[rounds])

            for key, value in parameters["fixedVariables"].items():
                stpcommands.assertVariableValue(stp_file, key, value)

            for char in parameters["blockedCharacteristics"]:
                stpcommands.blockCharacteristic(stp_file, char, wordsize)

            stpcommands.setupQuery(stp_file)

        return

    def setupTwineRound(self, stp_file, x_in, s, p, x_out, w, wordsize):
        """
        Model for differential behaviour of one round TWINE
        """
        command = ""

        # Substitution Layer
        twine_sbox = [0xC, 0, 0xF, 0xA, 2, 0xB, 9, 5, 8, 3, 0xD, 7, 1, 0xE, 6, 4]
        for i in range(8):
            variables = ["{0}[{1}:{1}]".format(x_in, 8*i + 3),
                         "{0}[{1}:{1}]".format(x_in, 8*i + 2),
                         "{0}[{1}:{1}]".format(x_in, 8*i + 1),
                         "{0}[{1}:{1}]".format(x_in, 8*i + 0),
                         "{0}[{1}:{1}]".format(s, 4*i + 3),
                         "{0}[{1}:{1}]".format(s, 4*i + 2),
                         "{0}[{1}:{1}]".format(s, 4*i + 1),
                         "{0}[{1}:{1}]".format(s, 4*i + 0),
                         "{0}[{1}:{1}]".format(w, 4*i + 3),
                         "{0}[{1}:{1}]".format(w, 4*i + 2),
                         "{0}[{1}:{1}]".format(w, 4*i + 1),
                         "{0}[{1}:{1}]".format(w, 4*i + 0)]
            command += stpcommands.add4bitSbox(twine_sbox, variables)

        #Feistel structure
        command += "ASSERT({0}[3:0] = {1}[3:0]);\n".format(x_in, p)
        command += "ASSERT({0}[11:8] = {1}[11:8]);\n".format(x_in, p)
        command += "ASSERT({0}[19:16] = {1}[19:16]);\n".format(x_in, p)
        command += "ASSERT({0}[27:24] = {1}[27:24]);\n".format(x_in, p)
        command += "ASSERT({0}[35:32] = {1}[35:32]);\n".format(x_in, p)
        command += "ASSERT({0}[43:40] = {1}[43:40]);\n".format(x_in, p)
        command += "ASSERT({0}[51:48] = {1}[51:48]);\n".format(x_in, p)
        command += "ASSERT({0}[59:56] = {1}[59:56]);\n".format(x_in, p)

        command += "ASSERT({0}[7:4] = BVXOR({1}[7:4],{2}[3:0]));\n".format(p, x_in, s)
        command += "ASSERT({0}[15:12] = BVXOR({1}[15:12],{2}[7:4]));\n".format(p, x_in, s)
        command += "ASSERT({0}[23:20] = BVXOR({1}[23:20],{2}[11:8]));\n".format(p, x_in, s)
        command += "ASSERT({0}[31:28] = BVXOR({1}[31:28],{2}[15:12]));\n".format(p, x_in, s)
        command += "ASSERT({0}[39:36] = BVXOR({1}[39:36],{2}[19:16]));\n".format(p, x_in, s)
        command += "ASSERT({0}[47:44] = BVXOR({1}[47:44],{2}[23:20]));\n".format(p, x_in, s)
        command += "ASSERT({0}[55:52] = BVXOR({1}[55:52],{2}[27:24]));\n".format(p, x_in, s)
        command += "ASSERT({0}[63:60] = BVXOR({1}[63:60],{2}[31:28]));\n".format(p, x_in, s)

        command += "ASSERT(0x00000000 = {0}[63:32]);\n".format(s)
        command += "ASSERT(0x00000000 = {0}[63:32]);\n".format(w)

        #Permutation Layer
        # pi = [5, 0, 1, 4, 7, 0xC, 3, 8, 0xD, 6, 9, 2, 0xF, 0xA, 0xB, 0xE]
        # 1 word = 4 bit
        command += "ASSERT({0}[3:0]   = {1}[23:20]);\n".format(p, x_out)	#0 -> 5
        command += "ASSERT({0}[7:4]   = {1}[3:0]);\n".format(p, x_out)		#1 -> 0
        command += "ASSERT({0}[11:8]  = {1}[7:4]);\n".format(p, x_out)		#2 -> 1
        command += "ASSERT({0}[15:12] = {1}[19:16]);\n".format(p, x_out) 	#3 -> 4
        command += "ASSERT({0}[19:16] = {1}[31:28]);\n".format(p, x_out)	#4 -> 7
        command += "ASSERT({0}[23:20] = {1}[51:48]);\n".format(p, x_out)	#5 -> 12
        command += "ASSERT({0}[27:24] = {1}[15:12]);\n".format(p, x_out)	#6 -> 3
        command += "ASSERT({0}[31:28] = {1}[35:32]);\n".format(p, x_out)	#7 -> 8
        command += "ASSERT({0}[35:32] = {1}[55:52]);\n".format(p, x_out)	#8 -> 13
        command += "ASSERT({0}[39:36] = {1}[27:24]);\n".format(p, x_out)	#9 -> 6
        command += "ASSERT({0}[43:40] = {1}[39:36]);\n".format(p, x_out)	#10 -> 9
        command += "ASSERT({0}[47:44] = {1}[11:8]);\n".format(p, x_out)		#11 -> 2
        command += "ASSERT({0}[51:48] = {1}[63:60]);\n".format(p, x_out)	#12 -> 15
        command += "ASSERT({0}[55:52] = {1}[43:40]);\n".format(p, x_out)	#13 -> 10
        command += "ASSERT({0}[59:56] = {1}[47:44]);\n".format(p, x_out)	#14 -> 11
        command += "ASSERT({0}[63:60] = {1}[59:56]);\n".format(p, x_out)	#15 -> 14


        stp_file.write(command)
        return
