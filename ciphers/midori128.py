'''
Created on Nov 15, 2017

@author: ralph
'''

from parser import stpcommands
from ciphers.cipher import AbstractCipher


class Midori128Cipher(AbstractCipher):
    """
    Represents the differential behaviour of Midori 128 and can be used
    to find differential characteristics for the given parameters.
    """

    name = "midori128"

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

        if wordsize != 128:
            print("Only wordsize of 128-bit supported.")
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
                sc, 8*idx + 7, 8*idx, mc, 8*val + 7, 8*val)

        #MixColumns
        # 0 1 1 1       x0      x1 + x2 + x3
        # 1 0 1 1       x1  ->  x0 + x2 + x3
        # 1 1 0 1       x2      x0 + x1 + x3
        # 1 1 1 0       x3      x0 + x1 + x2
        for col in range(4):
            for bit in range(8):
                offset0 = col*32 + 0 + bit
                offset1 = col*32 + 8 + bit
                offset2 = col*32 + 16 + bit
                offset3 = col*32 + 24 + bit

                command += "ASSERT(BVXOR(BVXOR({4}[{1}:{1}], {4}[{2}:{2}]), {4}[{3}:{3}]) \
                             = {5}[{0}:{0}]);\n".format(offset0, offset1, offset2, offset3, mc, sb_out)
                command += "ASSERT(BVXOR(BVXOR({4}[{0}:{0}], {4}[{2}:{2}]), {4}[{3}:{3}]) \
                             = {5}[{1}:{1}]);\n".format(offset0, offset1, offset2, offset3, mc, sb_out)
                command += "ASSERT(BVXOR(BVXOR({4}[{0}:{0}], {4}[{1}:{1}]), {4}[{3}:{3}]) \
                             = {5}[{2}:{2}]);\n".format(offset0, offset1, offset2, offset3, mc, sb_out)
                command += "ASSERT(BVXOR(BVXOR({4}[{0}:{0}], {4}[{1}:{1}]), {4}[{2}:{2}]) \
                             = {5}[{3}:{3}]);\n".format(offset0, offset1, offset2, offset3, mc, sb_out)


        # Substitution Layer
        midori_sbox_sb1 = [1, 0, 5, 3, 0xe, 2, 0xf, 7, 0xd, 0xa, 9, 0xb, 0xc, 8, 4, 6]
        for i in range(16):

            if i % 4 == 0:
                #SSB0
                #x[7,6,5,4,3,2,1,0]=y[4,1,6,3,0,5,2,7]

                variables_sbox1 = ["{0}[{1}:{1}]".format(sb_in, 8*i + 3), #msb  # 0
                                   "{0}[{1}:{1}]".format(sb_in, 8*i + 6),       # 1
                                   "{0}[{1}:{1}]".format(sb_in, 8*i + 1),       # 2
                                   "{0}[{1}:{1}]".format(sb_in, 8*i + 4), #lsb  # 3
                                   "{0}[{1}:{1}]".format(sc, 8*i + 3),      # 0
                                   "{0}[{1}:{1}]".format(sc, 8*i + 6),      # 1
                                   "{0}[{1}:{1}]".format(sc, 8*i + 1),      # 2
                                   "{0}[{1}:{1}]".format(sc, 8*i + 4),      # 3
                                   "{0}[{1}:{1}]".format(w, 8*i + 3),
                                   "{0}[{1}:{1}]".format(w, 8*i + 2),
                                   "{0}[{1}:{1}]".format(w, 8*i + 1),
                                   "{0}[{1}:{1}]".format(w, 8*i + 0)]

                variables_sbox2 = ["{0}[{1}:{1}]".format(sb_in, 8*i + 7), #msb  # 4
                                   "{0}[{1}:{1}]".format(sb_in, 8*i + 2),       # 5
                                   "{0}[{1}:{1}]".format(sb_in, 8*i + 5),       # 6
                                   "{0}[{1}:{1}]".format(sb_in, 8*i + 0), #lsb  # 7
                                   "{0}[{1}:{1}]".format(sc, 8*i + 7),      # 4
                                   "{0}[{1}:{1}]".format(sc, 8*i + 2),      # 5
                                   "{0}[{1}:{1}]".format(sc, 8*i + 5),      # 6
                                   "{0}[{1}:{1}]".format(sc, 8*i + 0),      # 7
                                   "{0}[{1}:{1}]".format(w, 8*i + 7),
                                   "{0}[{1}:{1}]".format(w, 8*i + 6),
                                   "{0}[{1}:{1}]".format(w, 8*i + 5),
                                   "{0}[{1}:{1}]".format(w, 8*i + 4)]

                command += stpcommands.add4bitSbox(midori_sbox_sb1, variables_sbox1)
                command += stpcommands.add4bitSbox(midori_sbox_sb1, variables_sbox2)
            elif i % 4 == 1:
                #SSB1
                #y[7,6,5,4,3,2,1,0]=x[3,0,5,6,7,4,1,2]

                variables_sbox1 = ["{0}[{1}:{1}]".format(sb_in, 8*i + 6), #msb  # 0
                                   "{0}[{1}:{1}]".format(sb_in, 8*i + 1),       # 1
                                   "{0}[{1}:{1}]".format(sb_in, 8*i + 0),       # 2
                                   "{0}[{1}:{1}]".format(sb_in, 8*i + 7), #lsb  # 3
                                   "{0}[{1}:{1}]".format(sc, 8*i + 6),      # 0
                                   "{0}[{1}:{1}]".format(sc, 8*i + 1),      # 1
                                   "{0}[{1}:{1}]".format(sc, 8*i + 0),      # 2
                                   "{0}[{1}:{1}]".format(sc, 8*i + 7),      # 3
                                   "{0}[{1}:{1}]".format(w, 8*i + 3),
                                   "{0}[{1}:{1}]".format(w, 8*i + 2),
                                   "{0}[{1}:{1}]".format(w, 8*i + 1),
                                   "{0}[{1}:{1}]".format(w, 8*i + 0)]

                variables_sbox2 = ["{0}[{1}:{1}]".format(sb_in, 8*i + 2), #msb  # 4
                                   "{0}[{1}:{1}]".format(sb_in, 8*i + 5),       # 5
                                   "{0}[{1}:{1}]".format(sb_in, 8*i + 4),       # 6
                                   "{0}[{1}:{1}]".format(sb_in, 8*i + 3), #lsb  # 7
                                   "{0}[{1}:{1}]".format(sc, 8*i + 2),      # 4
                                   "{0}[{1}:{1}]".format(sc, 8*i + 5),      # 5
                                   "{0}[{1}:{1}]".format(sc, 8*i + 4),      # 6
                                   "{0}[{1}:{1}]".format(sc, 8*i + 3),      # 7
                                   "{0}[{1}:{1}]".format(w, 8*i + 7),
                                   "{0}[{1}:{1}]".format(w, 8*i + 6),
                                   "{0}[{1}:{1}]".format(w, 8*i + 5),
                                   "{0}[{1}:{1}]".format(w, 8*i + 4)]

                command += stpcommands.add4bitSbox(midori_sbox_sb1, variables_sbox1)
                command += stpcommands.add4bitSbox(midori_sbox_sb1, variables_sbox2)
            elif i % 4 == 2:
                #SSB2
                #y[7,6,5,4,3,2,1,0]=x[6,3,0,1,2,7,4,5]

                variables_sbox1 = ["{0}[{1}:{1}]".format(sb_in, 8*i + 5), #msb  # 0
                                   "{0}[{1}:{1}]".format(sb_in, 8*i + 4),       # 1
                                   "{0}[{1}:{1}]".format(sb_in, 8*i + 3),       # 2
                                   "{0}[{1}:{1}]".format(sb_in, 8*i + 6), #lsb  # 3
                                   "{0}[{1}:{1}]".format(sc, 8*i + 5),      # 0
                                   "{0}[{1}:{1}]".format(sc, 8*i + 4),      # 1
                                   "{0}[{1}:{1}]".format(sc, 8*i + 3),      # 2
                                   "{0}[{1}:{1}]".format(sc, 8*i + 6),      # 3
                                   "{0}[{1}:{1}]".format(w, 8*i + 3),
                                   "{0}[{1}:{1}]".format(w, 8*i + 2),
                                   "{0}[{1}:{1}]".format(w, 8*i + 1),
                                   "{0}[{1}:{1}]".format(w, 8*i + 0)]

                variables_sbox2 = ["{0}[{1}:{1}]".format(sb_in, 8*i + 1), #msb  # 4
                                   "{0}[{1}:{1}]".format(sb_in, 8*i + 0),       # 5
                                   "{0}[{1}:{1}]".format(sb_in, 8*i + 7),       # 6
                                   "{0}[{1}:{1}]".format(sb_in, 8*i + 2), #lsb  # 7
                                   "{0}[{1}:{1}]".format(sc, 8*i + 1),      # 4
                                   "{0}[{1}:{1}]".format(sc, 8*i + 0),      # 5
                                   "{0}[{1}:{1}]".format(sc, 8*i + 7),      # 6
                                   "{0}[{1}:{1}]".format(sc, 8*i + 2),      # 7
                                   "{0}[{1}:{1}]".format(w, 8*i + 7),
                                   "{0}[{1}:{1}]".format(w, 8*i + 6),
                                   "{0}[{1}:{1}]".format(w, 8*i + 5),
                                   "{0}[{1}:{1}]".format(w, 8*i + 4)]

                command += stpcommands.add4bitSbox(midori_sbox_sb1, variables_sbox1)
                command += stpcommands.add4bitSbox(midori_sbox_sb1, variables_sbox2)
            elif i % 4 == 3:
                #SSB3
                #y[7,6,5,4,3,2,1,0]=x[5,2,3,4,1,6,7,0]

                variables_sbox1 = ["{0}[{1}:{1}]".format(sb_in, 8*i + 0), #msb  # 0
                                   "{0}[{1}:{1}]".format(sb_in, 8*i + 3),       # 1
                                   "{0}[{1}:{1}]".format(sb_in, 8*i + 6),       # 2
                                   "{0}[{1}:{1}]".format(sb_in, 8*i + 5), #lsb  # 3
                                   "{0}[{1}:{1}]".format(sc, 8*i + 0),      # 0
                                   "{0}[{1}:{1}]".format(sc, 8*i + 3),      # 1
                                   "{0}[{1}:{1}]".format(sc, 8*i + 6),      # 2
                                   "{0}[{1}:{1}]".format(sc, 8*i + 5),      # 3
                                   "{0}[{1}:{1}]".format(w, 8*i + 3),
                                   "{0}[{1}:{1}]".format(w, 8*i + 2),
                                   "{0}[{1}:{1}]".format(w, 8*i + 1),
                                   "{0}[{1}:{1}]".format(w, 8*i + 0)]

                variables_sbox2 = ["{0}[{1}:{1}]".format(sb_in, 8*i + 4), #msb  # 4
                                   "{0}[{1}:{1}]".format(sb_in, 8*i + 7),       # 5
                                   "{0}[{1}:{1}]".format(sb_in, 8*i + 2),       # 6
                                   "{0}[{1}:{1}]".format(sb_in, 8*i + 1), #lsb  # 7
                                   "{0}[{1}:{1}]".format(sc, 8*i + 4),      # 4
                                   "{0}[{1}:{1}]".format(sc, 8*i + 7),      # 5
                                   "{0}[{1}:{1}]".format(sc, 8*i + 2),      # 6
                                   "{0}[{1}:{1}]".format(sc, 8*i + 1),      # 7
                                   "{0}[{1}:{1}]".format(w, 8*i + 7),
                                   "{0}[{1}:{1}]".format(w, 8*i + 6),
                                   "{0}[{1}:{1}]".format(w, 8*i + 5),
                                   "{0}[{1}:{1}]".format(w, 8*i + 4)]

                command += stpcommands.add4bitSbox(midori_sbox_sb1, variables_sbox1)
                command += stpcommands.add4bitSbox(midori_sbox_sb1, variables_sbox2)
            else: 
                #something is seriously wrong!
                print("Error with modulo!")
                return

        stp_file.write(command)
        return
