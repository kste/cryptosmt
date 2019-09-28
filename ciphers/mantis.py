'''
Created on Apr 18, 2017

@author: ralph, kste
'''

from parser import stpcommands
from ciphers.cipher import AbstractCipher


class MantisCipher(AbstractCipher):
    """
    Represents the differential behaviour of Mantis and can be used
    to find differential characteristics for the given parameters.
    """

    name = "mantis"

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
        Creates an STP file to find a characteristic for Mantis with
        the given parameters.
        """

        wordsize = parameters["wordsize"]
        rounds = parameters["rounds"]
        weight = parameters["sweight"]

        if wordsize != 4:
            print("Mantis only supports a wordsize of 4 bits.")
            exit(1)

        if (rounds - 1) % 2 != 0:
            print("Mantis only supports a multiple of 2 as the number of rounds.")
            exit(1)

        with open(stp_filename, 'w') as stp_file:
            header = ("% Input File for STP\n% Mantis w={}"
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
                self.setupMantisForwardRound(stp_file, sb[si:ei], sr[si:ei], mc[si:ei],
                                             sb[ei:ei + 16], wn[si:ei], wordsize)

            # Middle round
            si = 16*(rounds // 2)
            ei = 16*((rounds // 2) + 1)
            self.setupMantisMiddleRound(stp_file, sb[si:ei], sr[si:ei], mc[si:ei],
                                        sb[ei:ei + 16], wn[si:ei], wn[ei:ei + 16],
                                        wordsize)

            # Backward round
            for rnd in range(rounds // 2 + 1, rounds):
                si = 16*rnd
                ei = 16*(rnd + 1)
                self.setupMantisBackwardRound(stp_file, sb[si:ei], sr[si:ei], mc[si:ei],
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

    def setupMantisForwardRound(self, stp_file, sb_in, sr, mc, sb_out, wn, wordsize):
        """
        Model for differential behaviour of one forward round Mantis.
        """
        command = ""

        # SubBytes
        mantis_sbox = [0xc, 0xa, 0xd, 0x3, 0xe, 0xb, 0xf, 0x7,
                       0x8, 0x9, 0x1, 0x5, 0x0, 0x2, 0x4, 0x6]

        for sbox in range(16):
            command += stpcommands.add4bitSboxNibbles(mantis_sbox, sb_in[sbox], sr[sbox], wn[sbox])

        # Permute Cells

        permutation = [0x0, 0xa, 0x5, 0xf, 0xe, 0x4, 0xb, 0x1,
                       0x9, 0x3, 0xc, 0x6, 0x7, 0xd, 0x2, 0x8]

        for nibble in range(16):
            command += "ASSERT({} = {});\n".format(sr[nibble], mc[permutation[nibble]])

        #MixColumns
        # 0 1 1 1       x0      x1 + x2 + x3
        # 1 0 1 1       x1  ->  x0 + x2 + x3
        # 1 1 0 1       x2      x0 + x1 + x3
        # 1 1 1 0       x3      x0 + x1 + x2

        for col in range(4):
            xorsum = stpcommands.getStringXORn(mc[4*col:(4*(col + 1))])  # Get One column
            for row in range(4):
                command += "ASSERT({} = BVXOR({}, {}));\n".format(sb_out[4*col + row],
                                                                  mc[4*col + row],
                                                                  xorsum)

        stp_file.write(command)
        return

    def setupMantisMiddleRound(self, stp_file, sb_in, m_in, m_out, sb_out, wn, wn2, wordsize):
        """
        Middle round of Mantis.
        """

        command = ""

        # SubBytes
        mantis_sbox = [0xc, 0xa, 0xd, 0x3, 0xe, 0xb, 0xf, 0x7,
                       0x8, 0x9, 0x1, 0x5, 0x0, 0x2, 0x4, 0x6]

        for sbox in range(16):
            command += stpcommands.add4bitSboxNibbles(mantis_sbox, sb_in[sbox], m_in[sbox], wn[sbox])

        # MixColumns
        for col in range(4):
            xorsum = stpcommands.getStringXORn(m_in[4*col:(4*(col + 1))])  # Get One column
            for row in range(4):
                command += "ASSERT({} = BVXOR({}, {}));\n".format(m_out[4*col + row],
                                                                  m_in[4*col + row],
                                                                  xorsum)

        # SubBytes
        for sbox in range(16):
            command += stpcommands.add4bitSboxNibbles(mantis_sbox, m_out[sbox], sb_out[sbox], wn2[sbox])

        stp_file.write(command)
        return

    def setupMantisBackwardRound(self, stp_file, sb_in, sr, mc, sb_out, wn, wordsize):
        """
        Model for differential behaviour of one backward round Mantis.
        """
        command = ""

        # MixColumns
        for col in range(4):
            xorsum = stpcommands.getStringXORn(sb_in[4*col:(4*(col + 1))])  # Get One column
            for row in range(4):
                command += "ASSERT({} = BVXOR({}, {}));\n".format(sr[4*col + row],
                                                                  sb_in[4*col + row],
                                                                  xorsum)

        # Permute Cells Inverse
        permutation = [0, 7, 14, 9, 5, 2, 11, 12,
                       15, 8, 1, 6, 10, 13, 4, 3]

        for nibble in range(16):
            command += "ASSERT({} = {});\n".format(sr[nibble], mc[permutation[nibble]])

        # Inverse SubBytes
        mantis_sbox = [0xc, 0xa, 0xd, 0x3, 0xe, 0xb, 0xf, 0x7,
                       0x8, 0x9, 0x1, 0x5, 0x0, 0x2, 0x4, 0x6]

        for sbox in range(16):
            command += stpcommands.add4bitSboxNibbles(mantis_sbox, mc[sbox], sb_out[sbox], wn[sbox])

        stp_file.write(command)
        return
