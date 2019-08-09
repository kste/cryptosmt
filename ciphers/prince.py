'''
Created on Jan 06, 2017

@author: ralph, kste
'''

from parser import stpcommands
from ciphers.cipher import AbstractCipher


class PrinceCipher(AbstractCipher):
    """
    Represents the differential behaviour of PRINCE and can be used
    to find differential characteristics for the given parameters.
    """

    name = "prince"

    def getFormatString(self):
        """
        Returns the print format.
        """
        sb = ['SB{}r'.format(i) for i in range(16)]
        mc = ['MC{}r'.format(i) for i in range(16)]
        sr = ['SR{}r'.format(i) for i in range(16)]
        return sb + mc + sr

    def createSTP(self, stp_filename, parameters):
        """
        Creates an STP file to find a characteristic for PRINCE with
        the given parameters.
        """

        wordsize = parameters["wordsize"]
        rounds = parameters["rounds"]
        weight = parameters["sweight"]

        if wordsize != 4:
            print("PRINCE only supports a wordsize of 4 bits.")
            exit(1)

        if (rounds - 1) % 2 != 0:
            print("PRINCE only supports a multiple of 2 as the number of rounds.")
            exit(1)

        with open(stp_filename, 'w') as stp_file:
            header = ("% Input File for STP\n% Prince w={}"
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
                self.setupPrinceForwardRound(stp_file, sb[si:ei], sr[si:ei], mc[si:ei],
                                             sb[ei:ei + 16], wn[si:ei], wordsize)

            # Middle round
            si = 16*(rounds // 2)
            ei = 16*((rounds // 2) + 1)
            self.setupPrinceMiddleRound(stp_file, sb[si:ei], sr[si:ei], mc[si:ei],
                                        sb[ei:ei + 16], wn[si:ei], wn[ei:ei + 16],
                                        wordsize)

            # Backward round
            for rnd in range(rounds // 2 + 1, rounds):
                si = 16*rnd
                ei = 16*(rnd + 1)
                self.setupPrinceBackwardRound(stp_file, sb[si:ei], sr[si:ei], mc[si:ei],
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

    def setupPrinceForwardRound(self, stp_file, sb_in, sr, mc, sb_out, wn, wordsize):
        """
        Model for differential behaviour of one forward round PRINCE.
        """
        command = ""

        # SubBytes
        prince_sbox = [0xb, 0xf, 0x3, 0x2, 0xa, 0xc, 0x9, 0x1,
                       0x6, 0x7, 0x8, 0x0, 0xe, 0x5, 0xd, 0x4]

        for sbox in range(16):
            command += stpcommands.add4bitSboxNibbles(prince_sbox, sb_in[sbox], mc[sbox], wn[sbox])

        # MixColumns
        for col in range(4):
            input_col = ["{0}[{1}:{1}]".format(mc[4*col + row], bit) for row in range(4) for bit in range(4)]
            output_col = ["{0}[{1}:{1}]".format(sr[4*col + row], bit) for row in range(4) for bit in range(4)]
            if col % 2 == 0:
                command += self.princeM(input_col, output_col)
            else:
                command += self.princeMhat(input_col, output_col)

        # ShiftRows
        permutation = [0, 5, 10, 15, 4, 9, 14, 3, 8, 13, 2, 7, 12, 1, 6, 11]
        for nibble in range(16):
            command += "ASSERT({} = {});\n".format(sr[nibble], sb_out[permutation[nibble]])

        stp_file.write(command)
        return

    def setupPrinceMiddleRound(self, stp_file, sb_in, sr, mc, sb_out, wn, wn2, wordsize):
        """
        Middle round of PRINCE.
        """

        command = ""

        # SubBytes
        prince_sbox = [0xb, 0xf, 0x3, 0x2, 0xa, 0xc, 0x9, 0x1,
                       0x6, 0x7, 0x8, 0x0, 0xe, 0x5, 0xd, 0x4]

        for sbox in range(16):
            command += stpcommands.add4bitSboxNibbles(prince_sbox, sb_in[sbox], mc[sbox], wn[sbox])

        # MixColumns
        for col in range(4):
            input_col = ["{0}[{1}:{1}]".format(mc[4*col + row], bit) for row in range(4) for bit in range(4)]
            output_col = ["{0}[{1}:{1}]".format(sr[4*col + row], bit) for row in range(4) for bit in range(4)]
            if col % 2 == 0:
                command += self.princeM(input_col, output_col)
            else:
                command += self.princeMhat(input_col, output_col)

        # Inverse SubBytes
        prince_sbox_inv = [0xb, 0x7, 0x3, 0x2, 0xf, 0xd, 0x8, 0x9,
                           0xa, 0x6, 0x4, 0x0, 0x5, 0xe, 0xc, 0x1]

        for sbox in range(16):
            command += stpcommands.add4bitSboxNibbles(prince_sbox_inv, sr[sbox], sb_out[sbox], wn2[sbox])

        stp_file.write(command)
        return

    def setupPrinceBackwardRound(self, stp_file, sb_in, sr, mc, sb_out, wn, wordsize):
        """
        Model for differential behaviour of one backward round PRINCE.
        """
        command = ""

        # ShiftRows
        permutation = [0, 13, 10, 7, 4, 1, 14, 11, 8, 5, 2, 15, 12, 9, 6, 3]
        for nibble in range(16):
            command += "ASSERT({} = {});\n".format(sb_in[nibble], sr[permutation[nibble]])

        # MixColumns
        for col in range(4):
            input_col = ["{0}[{1}:{1}]".format(sr[4*col + row], bit) for row in range(4) for bit in range(4)]
            output_col = ["{0}[{1}:{1}]".format(mc[4*col + row], bit) for row in range(4) for bit in range(4)]
            if col % 2 == 0:
                command += self.princeM(input_col, output_col)
            else:
                command += self.princeMhat(input_col, output_col)

        # Inverse SubBytes
        prince_sbox_inv = [0xb, 0x7, 0x3, 0x2, 0xf, 0xd, 0x8, 0x9,
                           0xa, 0x6, 0x4, 0x0, 0x5, 0xe, 0xc, 0x1]

        for sbox in range(16):
            command += stpcommands.add4bitSboxNibbles(prince_sbox_inv, mc[sbox], sb_out[sbox], wn[sbox])

        stp_file.write(command)
        return

    def princeM(self, input, output):
        # Add constraints for Prince M
        # input = (a0 a1 a2 a3 b0 b1 b2 b3 c0 c1 c2 c3 d0 d1 d2 d3)
        command = ""

        command += "ASSERT({} = {});\n".format(output[0], stpcommands.getStringXORn([input[0], input[4], input[8]]))
        command += "ASSERT({} = {});\n".format(output[1], stpcommands.getStringXORn([input[1], input[5], input[13]]))
        command += "ASSERT({} = {});\n".format(output[2], stpcommands.getStringXORn([input[2], input[10], input[14]]))
        command += "ASSERT({} = {});\n".format(output[3], stpcommands.getStringXORn([input[7], input[11], input[15]]))
        command += "ASSERT({} = {});\n".format(output[4], stpcommands.getStringXORn([input[0], input[4], input[12]]))
        command += "ASSERT({} = {});\n".format(output[5], stpcommands.getStringXORn([input[1], input[9], input[13]]))
        command += "ASSERT({} = {});\n".format(output[6], stpcommands.getStringXORn([input[6], input[10], input[14]]))
        command += "ASSERT({} = {});\n".format(output[7], stpcommands.getStringXORn([input[3], input[7], input[11]]))
        command += "ASSERT({} = {});\n".format(output[8], stpcommands.getStringXORn([input[0], input[8], input[12]]))
        command += "ASSERT({} = {});\n".format(output[9], stpcommands.getStringXORn([input[5], input[9], input[13]]))
        command += "ASSERT({} = {});\n".format(output[10], stpcommands.getStringXORn([input[2], input[6], input[10]]))
        command += "ASSERT({} = {});\n".format(output[11], stpcommands.getStringXORn([input[3], input[7], input[15]]))
        command += "ASSERT({} = {});\n".format(output[12], stpcommands.getStringXORn([input[4], input[8], input[12]]))
        command += "ASSERT({} = {});\n".format(output[13], stpcommands.getStringXORn([input[1], input[5], input[9]]))
        command += "ASSERT({} = {});\n".format(output[14], stpcommands.getStringXORn([input[2], input[6], input[14]]))
        command += "ASSERT({} = {});\n".format(output[15], stpcommands.getStringXORn([input[3], input[11], input[15]]))

        return command

    def princeMhat(self, input, output):
        # Add constraints for Prince M
        # input = (a0 a1 a2 a3 b0 b1 b2 b3 c0 c1 c2 c3 d0 d1 d2 d3)
        command = ""

        command += "ASSERT({} = {});\n".format(output[0], stpcommands.getStringXORn([input[0], input[4], input[12]]))
        command += "ASSERT({} = {});\n".format(output[1], stpcommands.getStringXORn([input[1], input[9], input[13]]))
        command += "ASSERT({} = {});\n".format(output[2], stpcommands.getStringXORn([input[6], input[10], input[14]]))
        command += "ASSERT({} = {});\n".format(output[3], stpcommands.getStringXORn([input[3], input[7], input[11]]))
        command += "ASSERT({} = {});\n".format(output[4], stpcommands.getStringXORn([input[0], input[8], input[12]]))
        command += "ASSERT({} = {});\n".format(output[5], stpcommands.getStringXORn([input[5], input[9], input[13]]))
        command += "ASSERT({} = {});\n".format(output[6], stpcommands.getStringXORn([input[2], input[6], input[10]]))
        command += "ASSERT({} = {});\n".format(output[7], stpcommands.getStringXORn([input[3], input[7], input[15]]))
        command += "ASSERT({} = {});\n".format(output[8], stpcommands.getStringXORn([input[4], input[8], input[12]]))
        command += "ASSERT({} = {});\n".format(output[9], stpcommands.getStringXORn([input[1], input[5], input[9]]))
        command += "ASSERT({} = {});\n".format(output[10], stpcommands.getStringXORn([input[2], input[6], input[14]]))
        command += "ASSERT({} = {});\n".format(output[11], stpcommands.getStringXORn([input[3], input[11], input[15]]))
        command += "ASSERT({} = {});\n".format(output[12], stpcommands.getStringXORn([input[0], input[4], input[8]]))
        command += "ASSERT({} = {});\n".format(output[13], stpcommands.getStringXORn([input[1], input[5], input[13]]))
        command += "ASSERT({} = {});\n".format(output[14], stpcommands.getStringXORn([input[2], input[10], input[14]]))
        command += "ASSERT({} = {});\n".format(output[15], stpcommands.getStringXORn([input[7], input[11], input[15]]))

        return command
