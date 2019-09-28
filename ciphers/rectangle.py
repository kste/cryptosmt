'''
Created on Sep 11, 2017

@author: ralph
'''

from parser import stpcommands
from ciphers.cipher import AbstractCipher


class RectangleCipher(AbstractCipher):
    """
    Represents the differential behaviour of RECTANGLE and can be used
    to find differential characteristics for the given parameters.
    """

    name = "rectangle"

    def getFormatString(self):
        """
        Returns the print format.
        """
        return ['SC', 'SR', 'w']

    def createSTP(self, stp_filename, parameters):
        """
        Creates an STP file to find a characteristic for RECTANGLE with
        the given parameters.
        """

        blocksize = parameters["blocksize"]
        wordsize = parameters["wordsize"]
        rounds = parameters["rounds"]
        weight = parameters["sweight"]

        with open(stp_filename, 'w') as stp_file:
            header = ("% Input File for STP\n% Rectangle w={}"
                      "rounds={}\n\n\n".format(blocksize, rounds))
            stp_file.write(header)

            # Setup variables
            sc = ["SC{}".format(i) for i in range(rounds + 1)]
            sr = ["SR{}".format(i) for i in range(rounds)]

            # w = weight
            w = ["w{}".format(i) for i in range(rounds)]

            stpcommands.setupVariables(stp_file, sc, blocksize)
            stpcommands.setupVariables(stp_file, sr, blocksize)
            stpcommands.setupVariables(stp_file, w, blocksize)

            stpcommands.setupWeightComputation(stp_file, weight, w, blocksize)

            for i in range(rounds):
                self.setupRectangleRound(stp_file, sc[i], sr[i], sc[i+1], 
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

    def setupRectangleRound(self, stp_file, sc_in, sr, sc_out, w, blocksize):
        """
        Model for differential behaviour of one round Rectangle
        """
        command = ""

        #SubColumn
        rectangle_sbox = [0x6, 0x5, 0xC, 0xA, 0x1, 0xE, 0x7, 0x9, 0xB, 0x0, 0x3, 0xD, 0x8, 0xF, 0x4, 0x2]
        for i in range(16):
            variables = ["{0}[{1}:{1}]".format(sc_in, i + 48),
                         "{0}[{1}:{1}]".format(sc_in, i + 32),
                         "{0}[{1}:{1}]".format(sc_in, i + 16),
                         "{0}[{1}:{1}]".format(sc_in, i + 0),
                         "{0}[{1}:{1}]".format(sr, i + 48),
                         "{0}[{1}:{1}]".format(sr, i + 32),
                         "{0}[{1}:{1}]".format(sr, i + 16),
                         "{0}[{1}:{1}]".format(sr, i + 0),
                         "{0}[{1}:{1}]".format(w, i + 48),
                         "{0}[{1}:{1}]".format(w, i + 32),
                         "{0}[{1}:{1}]".format(w, i + 16),
                         "{0}[{1}:{1}]".format(w, i + 0)]
            command += stpcommands.add4bitSbox(rectangle_sbox, variables)

        #ShiftRows
        # row 0 <<< 0
        command += "ASSERT({0}[15:0] = {1}[15:0]);\n".format(sr, sc_out)

        # row 1 <<< 1
        command += "ASSERT({0}[30:16] = {1}[31:17]);\n".format(sr, sc_out)
        command += "ASSERT({0}[31:31] = {1}[16:16]);\n".format(sr, sc_out)

        # row 2 <<< 12
        command += "ASSERT({0}[47:36] = {1}[43:32]);\n".format(sr, sc_out)
        command += "ASSERT({0}[35:32] = {1}[47:44]);\n".format(sr, sc_out)

        # row 3 <<< 13
        command += "ASSERT({0}[50:48] = {1}[63:61]);\n".format(sr, sc_out)
        command += "ASSERT({0}[63:51] = {1}[60:48]);\n".format(sr, sc_out)

        stp_file.write(command)
        return
