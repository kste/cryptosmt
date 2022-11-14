'''
Created on Mar 28, 2014

@author: stefan
'''

from parser import stpcommands
from ciphers.cipher import AbstractCipher

from parser.stpcommands import getStringRightRotate as rotr
from parser.stpcommands import getStringLeftRotate as rotl


class SpeckCipher(AbstractCipher):
    """
    Represents the differential behaviour of SPECK and can be used
    to find differential characteristics for the given parameters.
    """

    name = "speck"
    rot_alpha = 8
    rot_beta = 3

    def getFormatString(self):
        """
        Returns the print format.
        """
        return ['x', 'y', 'w']

    def createSTP(self, stp_filename, parameters):
        """
        Creates an STP file to find a characteristic for SPECK with
        the given parameters.
        """
        wordsize = parameters["wordsize"]
        rounds = parameters["rounds"]
        weight = parameters["sweight"]

        if wordsize == 16:
            self.rot_alpha = 7
            self.rot_beta = 2
        elif "rotationconstants" in parameters:
            self.rot_alpha = parameters["rotationconstants"][0]
            self.rot_beta = parameters["rotationconstants"][1]

        with open(stp_filename, 'w') as stp_file:
            stp_file.write("% Input File for STP\n% Speck w={} alpha={} beta={} "
                           "rounds={}\n\n\n".format(wordsize, self.rot_alpha,
                                                    self.rot_beta, rounds))

            # Setup variable
            # x = left, y = right
            # w = weight
            x = ["x{}".format(i) for i in range(rounds + 1)]
            y = ["y{}".format(i) for i in range(rounds + 1)]
            w = ["w{}".format(i) for i in range(rounds)]

            stpcommands.setupVariables(stp_file, x, wordsize)
            stpcommands.setupVariables(stp_file, y, wordsize)
            stpcommands.setupVariables(stp_file, w, wordsize)

            # Ignore MSB
            stpcommands.setupWeightComputation(stp_file, weight, w, wordsize, 1)

            for i in range(rounds):
                self.setupSpeckRound(stp_file, x[i], y[i], x[i+1], y[i+1], w[i],
                                     wordsize)

            # No all zero characteristic
            stpcommands.assertNonZero(stp_file, x + y, wordsize)

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

    def setupSpeckRound(self, stp_file, x_in, y_in, x_out, y_out, w, wordsize):
        """
        Model for differential behaviour of one round SPECK
        """
        command = ""

        #Assert(x_in >>> self.rot_alpha + y_in = x_out)
        command += "ASSERT("
        command += stpcommands.getStringAdd(rotr(x_in, self.rot_alpha, wordsize),
                                            y_in, x_out, wordsize)
        command += ");\n"

        #Assert(x_out xor (y_in <<< self.rot_beta) = x_in)
        command += "ASSERT(" + y_out + " = "
        command += "BVXOR(" + x_out + ","
        command += rotl(y_in, self.rot_beta, wordsize)
        command += "));\n"

        #For weight computation
        command += "ASSERT({0} = ~".format(w)
        command += stpcommands.getStringEq(rotr(x_in, self.rot_alpha, wordsize),
                                           y_in, x_out)
        command += ");\n"

        stp_file.write(command)
        return
