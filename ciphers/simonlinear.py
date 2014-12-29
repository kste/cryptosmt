'''
Created on Mar 28, 2014

@author: stefan
'''

from parser import stpcommands
from ciphers.cipher import AbstractCipher

from parser.stpcommands import getStringRightRotate as rotr


class SimonLinearCipher(AbstractCipher):
    """
    Represents the linear behaviour of SIMON and can be used
    to find differential characteristics for the given parameters.
    """

    def getName(self):
        """
        Returns the name of the cipher.
        """
        return "simonlinear"

    def getFormatString(self):
        """
        Returns the print format.
        """
        return ['x', 'y', 'w']

    def createSTP(self, stp_filename, cipherParameters):
        """
        Creates an STP file to find a linear characteristic for SIMON with
        the given parameters.
        """

        wordsize = cipherParameters[0]
        rot_alpha = cipherParameters[1]
        rot_beta = cipherParameters[2]
        rot_gamma = cipherParameters[3]
        rounds = cipherParameters[4]
        weight = cipherParameters[5]
        isIterative = cipherParameters[6]
        varsFixed = cipherParameters[7]
        blockedCharacteristics = cipherParameters[8]

        with open(stp_filename, 'w') as stp_file:
            stp_file.write("% Input File for STP\n% SimonLinear w={} alpha={} "
                           "beta={} gamma={} rounds={}\n\n\n".format(
                            wordsize, rot_alpha, rot_beta, rot_gamma, rounds))

            # Setup variable
            # x = left, y = right
            x = ["x{}".format(i) for i in range(rounds + 1)]
            y = ["y{}".format(i) for i in range(rounds + 1)]
            b = ["b{}".format(i) for i in range(rounds + 1)]
            c = ["c{}".format(i) for i in range(rounds + 1)]

            # w = weight
            w = ["w{}".format(i) for i in range(rounds)]

            stpcommands.setupVariables(stp_file, x, wordsize)
            stpcommands.setupVariables(stp_file, y, wordsize)
            stpcommands.setupVariables(stp_file, b, wordsize)
            stpcommands.setupVariables(stp_file, c, wordsize)
            stpcommands.setupVariables(stp_file, w, wordsize)

            stpcommands.setupWeightComputation(stp_file, weight, w, wordsize)

            for i in range(rounds):
                self.setupSimonRound(stp_file, x[i], y[i], x[i+1], y[i+1], b[i],
                                     c[i], w[i], rot_alpha, rot_beta, rot_gamma,
                                     wordsize)

            # No all zero characteristic
            stpcommands.assertNonZero(stp_file, x + y, wordsize)

            # Iterative characteristics only
            # Input difference = Output difference
            if isIterative:
                stpcommands.assertVariableValue(stp_file, x[0], x[rounds])
                stpcommands.assertVariableValue(stp_file, y[0], y[rounds])

            if varsFixed:
                for key, value in varsFixed.iteritems():
                    stpcommands.assertVariableValue(stp_file, key, value)

            if blockedCharacteristics:
                for char in blockedCharacteristics:
                    stpcommands.blockCharacteristic(stp_file, char, wordsize)

            stpcommands.setupQuery(stp_file)

        return

    def getParamList(self, rounds, wordsize, weight):
        """
        Returns a list of the parameters for SIMON.
        """
        return [wordsize, 1, 8, 2, rounds, weight]

    def setupSimonRound(self, stp_file, x_in, y_in, x_out, y_out, b, c, w,
                        rot_alpha, rot_beta, rot_gamma, wordsize):
        """
        Model for linear behaviour of one round SIMON.
        y[i+1] = x[i]
        x[i+1] = (x[i] <<< 1) & (x[i] <<< 8) ^ y[i] ^ (x[i] << 2)
        """
        command = ""

        #Assert(y_out = x_in)
        command += "ASSERT({} = {});\n".format(x_out, y_in)

        #Assert for AND linear approximation
        command += "ASSERT(((~{0} & ~{1} & ~{2}) | {0}) = 0hex{3});\n".format(
            y_in, b, c, "f"*(wordsize / 4))

        #Assert for y_out
        command += "ASSERT({0} = BVXOR({1}, BVXOR({2}, BVXOR({3}, {4}))));\n".format(
            y_out, x_in, rotr(c, rot_alpha, wordsize), rotr(b, rot_beta, wordsize),
            rotr(x_out, rot_gamma, wordsize))

        #For weight computation
        command += "ASSERT({0} = {1});".format(w, y_in)
        stp_file.write(command)
        return
