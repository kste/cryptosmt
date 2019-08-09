'''
Created on Jan 01, 2017

@author: ralph
'''

from parser import stpcommands
from ciphers.cipher import AbstractCipher


class MidoriCipher(AbstractCipher):
    """
    Represents the differential behaviour of Midori and can be used
    to find differential characteristics for the given parameters.
    """

    name = "midori"

    def getFormatString(self):
        """
        Returns the print format.
        """
        return ['SB', 'SC', 'MC', 'w']

    def createSTP(self, stp_filename, parameters):
        """
        Creates an STP file to find a characteristic for Midori with
        the given parameters.
        """

        wordsize = parameters["wordsize"]
        rounds = parameters["rounds"]
        weight = parameters["sweight"]

        if wordsize != 64:
            print("Only wordsize of 64-bit supported.")
            exit(1)

        with open(stp_filename, 'w') as stp_file:
            header = ("% Input File for STP\n% MIDORI w={}"
                      "rounds={}\n\n\n".format(wordsize, rounds))
            stp_file.write(header)

            # Setup variables
            sb = ["SB{}".format(i) for i in range(rounds + 1)]
            sc = ["SC{}".format(i) for i in range(rounds)]
            mc = ["MC{}".format(i) for i in range(rounds)]

            # w = weight
            w = ["w{}".format(i) for i in range(rounds)]

            stpcommands.setupVariables(stp_file, sb, wordsize)
            stpcommands.setupVariables(stp_file, sc, wordsize)
            stpcommands.setupVariables(stp_file, mc, wordsize)
            stpcommands.setupVariables(stp_file, w, wordsize)

            stpcommands.setupWeightComputation(stp_file, weight, w, wordsize)

            for i in range(rounds):
                self.setupMidoriRound(stp_file, sb[i], sc[i], mc[i], sb[i+1],
                                      w[i], wordsize)

            # No all zero characteristic
            stpcommands.assertNonZero(stp_file, sb, wordsize)

            # Iterative characteristics only
            # Input difference = Output difference
            if parameters["iterative"]:
                stpcommands.assertVariableValue(stp_file, sb[0], sb[rounds])

            for key, value in parameters["fixedVariables"].items():
                stpcommands.assertVariableValue(stp_file, key, value)

            for char in parameters["blockedCharacteristics"]:
                stpcommands.blockCharacteristic(stp_file, char, wordsize)

            stpcommands.setupQuery(stp_file)

        return

    def setupMidoriRound(self, stp_file, sb_in, sc, mc, sb_out, w, wordsize):
        """
        Model for differential behaviour of one round MIDORI
        """
        command = ""

        #Permutation Layer

        #ShuffleCells
        # 0 4 8 c       0 e 9 7
        # 1 5 9 d       a 4 3 d
        # 2 6 a e       5 b c 2
        # 3 7 b f       f 1 6 8

        permutation = [0x0, 0xa, 0x5, 0xf, 0xe, 0x4, 0xb, 0x1,
                       0x9, 0x3, 0xc, 0x6, 0x7, 0xd, 0x2, 0x8]

        for idx, val in enumerate(permutation):
            command += "ASSERT({0}[{1}:{2}] = {3}[{4}:{5}]);\n".format(
                sc, 4*val + 3, 4*val, mc, 4*idx + 3, 4*idx)

        #MixColumns
        # 0 1 1 1       x0      x1 + x2 + x3
        # 1 0 1 1       x1  ->  x0 + x2 + x3
        # 1 1 0 1       x2      x0 + x1 + x3
        # 1 1 1 0       x3      x0 + x1 + x2

        for col in range(4):
            for bit in range(4):
                offset0 = col*16 + 0 + bit
                offset1 = col*16 + 4 + bit
                offset2 = col*16 + 8 + bit
                offset3 = col*16 + 12 + bit

                command += "ASSERT(BVXOR(BVXOR({4}[{1}:{1}], {4}[{2}:{2}]), {4}[{3}:{3}]) \
                             = {5}[{0}:{0}]);\n".format(offset0, offset1, offset2, offset3, mc, sb_out)
                command += "ASSERT(BVXOR(BVXOR({4}[{0}:{0}], {4}[{2}:{2}]), {4}[{3}:{3}]) \
                             = {5}[{1}:{1}]);\n".format(offset0, offset1, offset2, offset3, mc, sb_out)
                command += "ASSERT(BVXOR(BVXOR({4}[{0}:{0}], {4}[{1}:{1}]), {4}[{3}:{3}]) \
                             = {5}[{2}:{2}]);\n".format(offset0, offset1, offset2, offset3, mc, sb_out)
                command += "ASSERT(BVXOR(BVXOR({4}[{0}:{0}], {4}[{1}:{1}]), {4}[{2}:{2}]) \
                             = {5}[{3}:{3}]);\n".format(offset0, offset1, offset2, offset3, mc, sb_out)


        # Substitution Layer
        midori_sbox = [0xc, 0xa, 0xd, 3, 0xe, 0xb, 0xf, 7, 8, 9, 1, 5, 0, 2, 4, 6]
        for i in range(16):
            variables = ["{0}[{1}:{1}]".format(sb_in, 4*i + 3),
                         "{0}[{1}:{1}]".format(sb_in, 4*i + 2),
                         "{0}[{1}:{1}]".format(sb_in, 4*i + 1),
                         "{0}[{1}:{1}]".format(sb_in, 4*i + 0),
                         "{0}[{1}:{1}]".format(sc, 4*i + 3),
                         "{0}[{1}:{1}]".format(sc, 4*i + 2),
                         "{0}[{1}:{1}]".format(sc, 4*i + 1),
                         "{0}[{1}:{1}]".format(sc, 4*i + 0),
                         "{0}[{1}:{1}]".format(w, 4*i + 3),
                         "{0}[{1}:{1}]".format(w, 4*i + 2),
                         "{0}[{1}:{1}]".format(w, 4*i + 1),
                         "{0}[{1}:{1}]".format(w, 4*i + 0)]
            command += stpcommands.add4bitSbox(midori_sbox, variables)

        stp_file.write(command)
        return
