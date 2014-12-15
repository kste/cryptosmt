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

    def getName(self):
        """
        Returns the name of the cipher.
        """
        return "speck"

    def getFormatString(self):
        """
        Returns the print format.
        """
        return ['x', 'y', 'w']

    def createSTP(self, stp_filename, cipherParameters):
        """
        Creates an STP file to find a characteristic for SPECK with
        the given parameters.
        """        
        wordsize = cipherParameters[0]
        rot_alpha = cipherParameters[1]
        rot_beta = cipherParameters[2]
        rounds = cipherParameters[3]
        weight = cipherParameters[4]
        is_iterative = cipherParameters[5]
        fixed_vars = cipherParameters[6]
        chars_blocked = cipherParameters[7]

        with open(stp_filename, 'w') as stp_file:
            stp_file.write("% Input File for STP\n% Speck w={} alpha={} beta={} "
                           "rounds={}\n\n\n".format(wordsize, rot_alpha, rot_beta,
                                                    rounds))

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
                                     rot_alpha, rot_beta, wordsize)

            # No all zero characteristic
            stpcommands.assertNonZero(stp_file, x + y, wordsize)

            # Iterative characteristics only
            # Input difference = Output difference
            if is_iterative:
                stpcommands.assertVariableValue(stp_file, x[0], x[rounds])
                stpcommands.assertVariableValue(stp_file, y[0], y[rounds])

            if fixed_vars:
                for key, value in fixed_vars.iteritems():
                    stpcommands.assertVariableValue(stp_file, key, value)

            if chars_blocked:
                for char in chars_blocked:
                    stpcommands.blockCharacteristic(stp_file, char, wordsize)

            stpcommands.setupQuery(stp_file)

        return

    def getParamList(self, rounds, wordsize, weight):
        """
        Returns a list of the parameters for SPECK.
        """
        if wordsize == 16:
            return [wordsize, 7, 2, rounds, weight]
        else:
            return [wordsize, 8, 3, rounds, weight]

    def setupSpeckRound(self, stp_file, x_in, y_in, x_out, y_out, w, rot_alpha,
                        rot_beta, wordsize):
        """
        Model for differential behaviour of one round SPECK
        """
        command = ""

        #Assert(x_in >>> rot_alpha + y_in = x_out)
        command += "ASSERT("
        command += stpcommands.getStringAdd(rotr(x_in, rot_alpha, wordsize),
                                            y_in, x_out, wordsize)
        command += ");\n"

        #Assert(x_out xor (y_in <<< rot_beta) = x_in)
        command += "ASSERT(" + y_out + " = "
        command += "BVXOR(" + x_out + ","
        command += rotl(y_in, rot_beta, wordsize)
        command += "));\n"

        #For weight computation
        command += "ASSERT({0} = ~".format(w)
        command += stpcommands.getStringEq(rotr(x_in, rot_alpha, wordsize),
                                           y_in, x_out, wordsize)
        command += ");\n"

        stp_file.write(command)
        return
