'''
Created on Jan 6, 2016

@author: stefan
'''

from parser import stpcommands
from ciphers.cipher import AbstractCipher

from parser.stpcommands import getStringLeftRotate as rotl


class SalsaCipher(AbstractCipher):
    """
    Represents the differential behaviour of the Salsa stream cipher by
    Daniel J. Bernstein and can be used to find differential trails for the 
    given parameters.

    For more information on ChaCha see http://cr.yp.to/snuffle.html
    """

    name = "salsa"

    def getFormatString(self):
        """
        Returns the print format.
        """
        return ['a0r', 'a1r', 'a2r', 'a3r',
                'a4r', 'a5r', 'a6r', 'a7r',
                'a8r', 'a9r', 'a10r', 'a11r',
                'a12r', 'a13r', 'a14r', 'a15r'
                #'w0r', 'w1r', 'w2r', 'w3r',
                # 'w4r', 'w5r', 'w6r', 'w7r',
                # 'w8r', 'w9r', 'w10r', 'w11r',
                # 'w12r', 'w13r', 'w14r', 'w15r'
               ]

    def createSTP(self, stp_filename, parameters):
        """
        Creates an STP file to find a characteristic for Salsa with
        the given parameters.
        """
        wordsize = parameters["wordsize"]
        rounds = parameters["rounds"]
        weight = parameters["sweight"]

        with open(stp_filename, 'w') as stp_file:
            stp_file.write("% Input File for STP\n% Salsa w={}"
                           "rounds={}\n\n\n".format(wordsize, rounds))

            # Setup variables
            a = ["a{}r{}".format(j, i) for i in range(rounds + 1) for j in range(16)]
            b = ["b{}r{}".format(j, i) for i in range(rounds) for j in range(16)]
            w = ["w{}r{}".format(j, i) for i in range(rounds) for j in range(16)]

            stpcommands.setupVariables(stp_file, a, wordsize)
            stpcommands.setupVariables(stp_file, b, wordsize)
            stpcommands.setupVariables(stp_file, w, wordsize)

            # Ignore MSB
            stpcommands.setupWeightComputation(stp_file, weight, w, wordsize, 1)

            for rnd in range(rounds):
                if rnd % 2 != 0:
                    #Rowround
                    for row in range(4):
                        a_in = [a[(i + row) % 4 + 4 * row + 16 * rnd] for i in range(4)]
                        a_out = [a[(i + row) % 4 + 4 * row + 16 * (rnd + 1)] for i in range(4)]
                        tmp_b = [b[i + 4 * row + 16 * rnd] for i in range(4)]
                        tmp_w = [w[i + 4 * row + 16 * rnd] for i in range(4)]
                        self.setupQuarterRound(stp_file, a_in, tmp_b, a_out, tmp_w, wordsize)
                else:
                    #Columnround
                    for col in range(4): 
                        a_in = [a[(i * 4 + 4 * col + col) % 16 + 16 * rnd] for i in range(4)]
                        a_out = [a[(i * 4 + 4 * col + col) % 16 + 16 * (rnd + 1)] for i in range(4)]
                        tmp_b = [b[i * 4 + col + 16 * rnd] for i in range(4)]
                        tmp_w = [w[i * 4 + col + 16 * rnd] for i in range(4)]
                        self.setupQuarterRound(stp_file, a_in, tmp_b, a_out, tmp_w, wordsize)

            #stp_file.write("ASSERT(({}[31:31]) = 0b0);\n".format(a[0]))
            # No all zero characteristic
            stpcommands.assertNonZero(stp_file, a, wordsize)

            for key, value in parameters["fixedVariables"].items():
                stpcommands.assertVariableValue(stp_file, key, value)

            for char in parameters["blockedCharacteristics"]:
                stpcommands.blockCharacteristic(stp_file, char, wordsize)

            stpcommands.setupQuery(stp_file)

        return

    def setupQuarterRound(self, stp_file, a, b, c, w, wordsize):
        """
        Salsa quarter round:
            (c0, c1, c2, c3) = Quarterround(a0, a1, a2, a3)
            b0, b1, b2 and b3 are used for the modular addition.
        """
        command = ""
        # First addition
        command += "ASSERT({});\n".format(
            stpcommands.getStringAdd(a[0], a[3], b[0], wordsize))

        command += "ASSERT({} = ~{});\n".format(w[0],
            stpcommands.getStringEq(a[0], a[3], b[0]))


        # Second addition
        tmp_xor0 = "BVXOR({}, {})".format(rotl(b[0], 7, wordsize), a[1])
        command += "ASSERT({});\n".format(
            stpcommands.getStringAdd(a[0], tmp_xor0, b[1], wordsize))

        command += "ASSERT({} = ~{});\n".format(w[1],
            stpcommands.getStringEq(a[0], tmp_xor0, b[1]))


        # Third addition
        tmp_xor1 = "BVXOR({}, {})".format(rotl(b[1], 9, wordsize), a[2])
        command += "ASSERT({});\n".format(
            stpcommands.getStringAdd(tmp_xor0, tmp_xor1, b[2], wordsize))

        command += "ASSERT({} = ~{});\n".format(w[2],
            stpcommands.getStringEq(tmp_xor0, tmp_xor1, b[2]))

        # Fourth addition
        tmp_xor2 = "BVXOR({}, {})".format(rotl(b[2], 13, wordsize), a[3])
        command += "ASSERT({});\n".format(
            stpcommands.getStringAdd(tmp_xor1, tmp_xor2, b[3], wordsize))

        command += "ASSERT({} = ~{});\n".format(w[3],
            stpcommands.getStringEq(tmp_xor1, tmp_xor2, b[3]))

        # Outputs
        command += "ASSERT({} = BVXOR({}, {}));\n".format(c[0], a[0], rotl(b[3], 18, wordsize))
        command += "ASSERT({} = {});\n".format(c[1], tmp_xor0)
        command += "ASSERT({} = {});\n".format(c[2], tmp_xor1)
        command += "ASSERT({} = {});\n".format(c[3], tmp_xor2)

        stp_file.write(command)
        return
