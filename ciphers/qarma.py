'''
Created on Aug 18, 2017

@author: ralph, kste
'''

from parser import stpcommands
from ciphers.cipher import AbstractCipher


class QarmaCipher(AbstractCipher):
    """
    Represents the differential behaviour of Qarma and can be used
    to find differential characteristics for the given parameters.
    """

    name = "qarma"

    #Sboxes
    #default sbox = sigma1
    #qarma sigma0 = [0x0, 0xE, 0x2, 0xA, 0x9, 0xF, 0x8, 0xB, 0x6, 0x4, 0x3, 0x7, 0xD, 0xC, 0x1, 0x5]
    #qarma sigma1 = [0xA, 0xD. 0xE, 0x6, 0xF, 0x7, 0x3, 0x5, 0x9, 0x8, 0x0, 0xC, 0xB, 0x1, 0x2, 0x4]
    #qarma sigma2 = [0xB, 0x6, 0x8, 0xF, 0xC, 0x0, 0x9, 0xE, 0x3, 0x7, 0x4, 0x5, 0xD, 0x2, 0x1, 0xA]
    #qarma sigma2_inv = [0x5, 0xE, 0xD, 0x8, 0xA, 0xB, 0x1, 0x9, 0x2, 0x6, 0xF, 0x0, 0x4, 0xC, 0x7, 0x3]



    def getFormatString(self):
        """
        Returns the print format.
        """
        sb = ['SB{}r'.format(i) for i in range(16)]
        sr = ['SR{}r'.format(i) for i in range(16)]
        mc = ['MC{}r'.format(i) for i in range(16)]
        return sb + sr + mc

    def createSTP(self, stp_filename, parameters):
        """
        Creates an STP file to find a characteristic for Qarma with
        the given parameters.
        """

        wordsize = parameters["wordsize"]
        rounds = parameters["rounds"]
        weight = parameters["sweight"]

        if wordsize != 4:
            print("Qarma only supports a wordsize of 4 bits.")
            exit(1)

        if (rounds - 1) % 2 != 0:
            print("Qarma only supports a multiple of 2 as the number of rounds.")
            exit(1)

        with open(stp_filename, 'w') as stp_file:
            header = ("% Input File for STP\n% Qarma w={}"
                      "rounds={}\n\n\n".format(wordsize, rounds))
            stp_file.write(header)

            # Setup variables
            # State is represented as nibbles
            # 0 4  8 12
            # 1 5  9 13
            # 2 6 10 14
            # 3 7 11 15

            sb = ["SB{}r{}".format(j, i) for i in range(rounds + 1) for j in range(16)]
            sr = ["SR{}r{}".format(j, i) for i in range(rounds) for j in range(16)]
            mc = ["MC{}r{}".format(j, i) for i in range(rounds) for j in range(16)]

            # wn = weight of each S-box
            wn = ["wn{}r{}".format(j, i) for i in range(rounds + 1) for j in range(16)]  # One Extra for middle round

            stpcommands.setupVariables(stp_file, sb, wordsize)
            stpcommands.setupVariables(stp_file, sr, wordsize)
            stpcommands.setupVariables(stp_file, mc, wordsize)
            stpcommands.setupVariables(stp_file, wn, wordsize)

            stpcommands.setupWeightComputation(stp_file, weight, wn, wordsize)

            # Forward rounds
            for rnd in range(rounds // 2):
                si = 16*rnd
                ei = 16*(rnd + 1)
                self.setupQarmaForwardRound(stp_file, sb[si:ei], sr[si:ei], mc[si:ei],
                                             sb[ei:ei + 16], wn[si:ei], wordsize)

            # Middle round
            si = 16*(rounds // 2)
            ei = 16*((rounds // 2) + 1)
            self.setupQarmaMiddleRound(stp_file, sb[si:ei], sr[si:ei], mc[si:ei],
                                        sb[ei:ei + 16], wn[si:ei], wn[ei:ei + 16],
                                        wordsize)

            # Backward round
            for rnd in range(rounds // 2 + 1, rounds):
                si = 16*rnd
                ei = 16*(rnd + 1)
                self.setupQarmaBackwardRound(stp_file, sb[si:ei], sr[si:ei], mc[si:ei],
                                              sb[ei:ei + 16], wn[si + 16:ei + 16], wordsize)


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

    def setupQarmaForwardRound(self, stp_file, sb_in, sr, mc, sb_out, wn, wordsize):
        """
        Model for differential behaviour of one forward round Qarma.
        """
        command = ""

        # Shuffle Cells - Midori cell permutation
        # 0 4 8 c       0 e 9 7
        # 1 5 9 d       a 4 3 d
        # 2 6 a e       5 b c 2
        # 3 7 b f       f 1 6 8
        permutation = [0x0, 0xa, 0x5, 0xf, 0xe, 0x4, 0xb, 0x1,
                       0x9, 0x3, 0xc, 0x6, 0x7, 0xd, 0x2, 0x8]

        for nibble in range(16):
            command += "ASSERT({} = {});\n".format(sr[nibble], mc[permutation[nibble]])

        # MixColumns
        # M4,2 = Q4,2 = [0, 1, 2, 1,
        #                1, 0, 1, 2,
        #                2, 1, 0, 1,
        #                1, 2, 1, 0]

        # 0 1 1 1       x0      x1 + x2 + x3
        # 1 0 1 1       x1  ->  x0 + x2 + x3
        # 1 1 0 1       x2      x0 + x1 + x3
        # 1 1 1 0       x3      x0 + x1 + x2

        #for col in range(4):
        #    for bit in range(4):
        #        offset0 = col*16 + 0 + bit
        #        offset1 = col*16 + 4 + bit
        #        offset2 = col*16 + 8 + bit
        #        offset3 = col*16 + 12 + bit

        #        command += "ASSERT(BVXOR(BVXOR({4}[{1}:{1}], {4}[{2}:{2}]), {4}[{3}:{3}]) \
        #                     = {5}[{0}:{0}]);\n".format(offset0, offset1, offset2, offset3, mc, sb_out)
        #        command += "ASSERT(BVXOR(BVXOR({4}[{0}:{0}], {4}[{2}:{2}]), {4}[{3}:{3}]) \
        #                     = {5}[{1}:{1}]);\n".format(offset0, offset1, offset2, offset3, mc, sb_out)
        #        command += "ASSERT(BVXOR(BVXOR({4}[{0}:{0}], {4}[{1}:{1}]), {4}[{3}:{3}]) \
        #                     = {5}[{2}:{2}]);\n".format(offset0, offset1, offset2, offset3, mc, sb_out)
        #        command += "ASSERT(BVXOR(BVXOR({4}[{0}:{0}], {4}[{1}:{1}]), {4}[{2}:{2}]) \
        #                     = {5}[{3}:{3}]);\n".format(offset0, offset1, offset2, offset3, mc, sb_out)

        # SubCells
        # Sboxes
        # default sbox = sigma1
        # qarma sigma0 = [0x0, 0xE, 0x2, 0xA, 0x9, 0xF, 0x8, 0xB, 0x6, 0x4, 0x3, 0x7, 0xD, 0xC, 0x1, 0x5]
        # qarma sigma1 = [0xA, 0xD. 0xE, 0x6, 0xF, 0x7, 0x3, 0x5, 0x9, 0x8, 0x0, 0xC, 0xB, 0x1, 0x2, 0x4]
        # qarma sigma2 = [0xB, 0x6, 0x8, 0xF, 0xC, 0x0, 0x9, 0xE, 0x3, 0x7, 0x4, 0x5, 0xD, 0x2, 0x1, 0xA]
        # qarma sigma2_inv = [0x5, 0xE, 0xD, 0x8, 0xA, 0xB, 0x1, 0x9, 0x2, 0x6, 0xF, 0x0, 0x4, 0xC, 0x7, 0x3]
        qarma_sbox_sigma_1 = [0xA, 0xD. 0xE, 0x6, 0xF, 0x7, 0x3, 0x5, 0x9, 0x8, 0x0, 0xC, 0xB, 0x1, 0x2, 0x4]

        for sbox in range(16):
            command += stpcommands.add4bitSboxNibbles(qarama_sbox_sigma_1, sb_in[sbox], sr[sbox], wn[sbox])


        stp_file.write(command)
        return

    def setupQarmaMiddleRound(self, stp_file, sb_in, m_in, m_out, sb_out, wn, wn2, wordsize):
        """
        Middle round of Qarma.
        """

        command = ""

        # 1 forward round
        self.setupQarmaForwardRound(stp_file, sb[si:ei], sr[si:ei], mc[si:ei],
                                             sb[ei:ei + 16], wn[si:ei], wordsize)

        # Shuffle Cells - Midori cell permutation
        # 0 4 8 c       0 e 9 7
        # 1 5 9 d       a 4 3 d
        # 2 6 a e       5 b c 2
        # 3 7 b f       f 1 6 8
        permutation = [0x0, 0xa, 0x5, 0xf, 0xe, 0x4, 0xb, 0x1,
                       0x9, 0x3, 0xc, 0x6, 0x7, 0xd, 0x2, 0x8]

        for nibble in range(16):
            command += "ASSERT({} = {});\n".format(sr[nibble], mc[permutation[nibble]])

        # MixColumns
        # M4,2 = Q4,2 = [0, 1, 2, 1,
        #                1, 0, 1, 2,
        #                2, 1, 0, 1,
        #                1, 2, 1, 0]

        #TODO
        #for col in range(4):
        #    xorsum = stpcommands.getStringXORn(mc[4*col:(4*(col + 1))])  # Get One column
        #    for row in range(4):
        #        command += "ASSERT({} = BVXOR({}, {}));\n".format(sb_out[4*col + row],
        #                                                          sr[4*col + row],
        #                                                          xorsum)

        # ShuffleCells inverse - Midori cell permutation
        # 0 4 8 c       0 5 f a
        # 1 5 9 d       7 2 8 d
        # 2 6 a e       e b 1 4
        # 3 7 b f       9 c 6 3
        permutation_inv = [0x0, 0x7, 0xe, 0x9, 0x5, 0x2, 0xb, 0xc,
                       0xf, 0x8, 0x1, 0x6, 0xa, 0xd, 0x4, 0x3]

        for nibble in range(16):
            command += "ASSERT({} = {});\n".format(sr[nibble], mc[permutation_inv[nibble]])


        # 1 backward round
        self.setupQarmaBackwardRound(stp_file, sb[si:ei], sr[si:ei], mc[si:ei],
                                     sb[ei:ei + 16], wn[si + 16:ei + 16], wordsize)

        stp_file.write(command)
        return

    def setupQarmaBackwardRound(self, stp_file, sb_in, sr, mc, sb_out, wn, wordsize):
        """
        Model for differential behaviour of one backward round Qarma.
        """
        command = ""

        # SubCells
        # Sboxes
        # default sbox = sigma1
        # qarma sigma0 = [0x0, 0xE, 0x2, 0xA, 0x9, 0xF, 0x8, 0xB, 0x6, 0x4, 0x3, 0x7, 0xD, 0xC, 0x1, 0x5]
        # qarma sigma1 = [0xA, 0xD. 0xE, 0x6, 0xF, 0x7, 0x3, 0x5, 0x9, 0x8, 0x0, 0xC, 0xB, 0x1, 0x2, 0x4]
        # qarma sigma2 = [0xB, 0x6, 0x8, 0xF, 0xC, 0x0, 0x9, 0xE, 0x3, 0x7, 0x4, 0x5, 0xD, 0x2, 0x1, 0xA]
        # qarma sigma2_inv = [0x5, 0xE, 0xD, 0x8, 0xA, 0xB, 0x1, 0x9, 0x2, 0x6, 0xF, 0x0, 0x4, 0xC, 0x7, 0x3]
        qarma_sbox_sigma_1 = [0xA, 0xD. 0xE, 0x6, 0xF, 0x7, 0x3, 0x5, 0x9, 0x8, 0x0, 0xC, 0xB, 0x1, 0x2, 0x4]

        for sbox in range(16):
            command += stpcommands.add4bitSboxNibbles(qarama_sbox_sigma_1, sb_in[sbox], sr[sbox], wn[sbox])

        # MixColumns
        # M4,2 = Q4,2 = [0, 1, 2, 1,
        #                1, 0, 1, 2,
        #                2, 1, 0, 1,
        #                1, 2, 1, 0]

        #TODO
        #for col in range(4):
        #    xorsum = stpcommands.getStringXORn(sb_in[4*col:(4*(col + 1))])  # Get One column
        #    for row in range(4):
        #        command += "ASSERT({} = BVXOR({}, {}));\n".format(sr[4*col + row],
        #                                                          sb_in[4*col + row],
        #                                                          xorsum)

        # ShuffleCells inverse - Midori cell permutation
        # 0 4 8 c       0 5 f a
        # 1 5 9 d       7 2 8 d
        # 2 6 a e       e b 1 4
        # 3 7 b f       9 c 6 3
        permutation = [0x0, 0x7, 0xe, 0x9, 0x5, 0x2, 0xb, 0xc,
                       0xf, 0x8, 0x1, 0x6, 0xa, 0xd, 0x4, 0x3]

        for nibble in range(16):
            command += "ASSERT({} = {});\n".format(sr[nibble], mc[permutation[nibble]])

        stp_file.write(command)
        return

    def setupQarmaFirstForwardRound(self, stp_file, sb_in, sr, mc, sb_out, wn, wordsize):
        """
        Model for differential behaviour of the first forward round Qarma.
        """
        command = ""

        # SubCells
        # Sboxes
        # default sbox = sigma1
        # qarma sigma0 = [0x0, 0xE, 0x2, 0xA, 0x9, 0xF, 0x8, 0xB, 0x6, 0x4, 0x3, 0x7, 0xD, 0xC, 0x1, 0x5]
        # qarma sigma1 = [0xA, 0xD. 0xE, 0x6, 0xF, 0x7, 0x3, 0x5, 0x9, 0x8, 0x0, 0xC, 0xB, 0x1, 0x2, 0x4]
        # qarma sigma2 = [0xB, 0x6, 0x8, 0xF, 0xC, 0x0, 0x9, 0xE, 0x3, 0x7, 0x4, 0x5, 0xD, 0x2, 0x1, 0xA]
        # qarma sigma2_inv = [0x5, 0xE, 0xD, 0x8, 0xA, 0xB, 0x1, 0x9, 0x2, 0x6, 0xF, 0x0, 0x4, 0xC, 0x7, 0x3]
        qarma_sbox_sigma_1 = [0xA, 0xD. 0xE, 0x6, 0xF, 0x7, 0x3, 0x5, 0x9, 0x8, 0x0, 0xC, 0xB, 0x1, 0x2, 0x4]

        for sbox in range(16):
            command += stpcommands.add4bitSboxNibbles(qarama_sbox_sigma_1, sb_in[sbox], sr[sbox], wn[sbox])

        stp_file.write(command)
        return

    def setupQarmaLastBackwardRound(self, stp_file, sb_in, sr, mc, sb_out, wn, wordsize):
        """
        Model for differential behaviour of the last backward round Qarma.
        """
        command = ""

        # SubCells
        # Sboxes
        # default sbox = sigma1
        # qarma sigma0 = [0x0, 0xE, 0x2, 0xA, 0x9, 0xF, 0x8, 0xB, 0x6, 0x4, 0x3, 0x7, 0xD, 0xC, 0x1, 0x5]
        # qarma sigma1 = [0xA, 0xD. 0xE, 0x6, 0xF, 0x7, 0x3, 0x5, 0x9, 0x8, 0x0, 0xC, 0xB, 0x1, 0x2, 0x4]
        # qarma sigma2 = [0xB, 0x6, 0x8, 0xF, 0xC, 0x0, 0x9, 0xE, 0x3, 0x7, 0x4, 0x5, 0xD, 0x2, 0x1, 0xA]
        # qarma sigma2_inv = [0x5, 0xE, 0xD, 0x8, 0xA, 0xB, 0x1, 0x9, 0x2, 0x6, 0xF, 0x0, 0x4, 0xC, 0x7, 0x3]
        qarma_sbox_sigma_1 = [0xA, 0xD. 0xE, 0x6, 0xF, 0x7, 0x3, 0x5, 0x9, 0x8, 0x0, 0xC, 0xB, 0x1, 0x2, 0x4]

        for sbox in range(16):
            command += stpcommands.add4bitSboxNibbles(qarama_sbox_sigma_1, sb_in[sbox], sr[sbox], wn[sbox])

        stp_file.write(command)
        return
