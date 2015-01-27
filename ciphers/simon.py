'''
Created on Mar 28, 2014

@author: stefan
'''

from parser import stpcommands
from ciphers.cipher import AbstractCipher

from parser.stpcommands import getStringLeftRotate as rotl
from parser.stpcommands import getStringRightRotate as rotr


class SimonCipher(AbstractCipher):
    """
    Represents the differential behaviour of SIMON and can be used
    to find differential characteristics for the given parameters.
    """

    def getName(self):
        """
        Returns the name of the cipher.
        """
        return "simon"

    def getFormatString(self):
        """
        Returns the print format.
        """
        return ['x', 'y', 'w']

    def createSTP(self, stp_filename, cipherParameters):
        """
        Creates an STP file to find a characteristic for SIMON with
        the given parameters.
        """

        wordsize = cipherParameters[0]
        rot_alpha = cipherParameters[1]
        rot_beta = cipherParameters[2]
        rot_gamma = cipherParameters[3]
        rounds = cipherParameters[4]
        weight = cipherParameters[5]
        is_iterative = cipherParameters[6]
        fixed_vars = cipherParameters[7]
        chars_blocked = cipherParameters[8]

        with open(stp_filename, 'w') as stp_file:
            stp_file.write("% Input File for STP\n% Simon w={} alpha={} beta={} gamma={}"
                           " rounds={}\n\n\n".format(wordsize, rot_alpha, rot_beta,
                                                     rot_gamma, rounds))

            # Setup variables
            # x = left, y = right
            x = ["x{}".format(i) for i in range(rounds + 1)]
            y = ["y{}".format(i) for i in range(rounds + 1)]
            and_out = ["andout{}".format(i) for i in range(rounds + 1)]

            # w = weight
            w = ["w{}".format(i) for i in range(rounds)]

            stpcommands.setupVariables(stp_file, x, wordsize)
            stpcommands.setupVariables(stp_file, y, wordsize)
            stpcommands.setupVariables(stp_file, and_out, wordsize)
            stpcommands.setupVariables(stp_file, w, wordsize)

            stpcommands.setupWeightComputation(stp_file, weight, w, wordsize)

            for i in range(rounds):
                self.setupSimonRound(stp_file, x[i], y[i], x[i+1], y[i+1], and_out[i],
                                     w[i], rot_alpha, rot_beta, rot_gamma, wordsize)

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
        Returns a list of the parameters for SIMON.
        """
        return [wordsize, 8, 1, 2, rounds, weight]

    def setupSimonRound(self, stp_file, x_in, y_in, x_out, y_out, and_out, w,
                        rot_alpha, rot_beta, rot_gamma, wordsize):
        """
        Model for differential behaviour of one round SIMON
        y[i+1] = x[i]
        x[i+1] = (x[i] <<< 1) & (x[i] <<< 8) ^ y[i] ^ (x[i] << 2)

        This model is only correct if gcd(rot_alpha - rot_beta, wordsize) = 1
        and rot_alpha > rot_beta
        """
        command = ""

        #Assert(y_out = x_in)
        command += "ASSERT({} = {});\n".format(y_out, x_in)

        x_in_rotalpha = rotl(x_in, rot_alpha, wordsize)
        x_in_rotbeta = rotl(x_in, rot_beta, wordsize)

                #Deal with dependent inputs
        varibits = "({0} | {1})".format(x_in_rotalpha, x_in_rotbeta)
        doublebits = self.getDoubleBits(x_in, rot_alpha, rot_beta, wordsize)

        #Check for valid difference
        firstCheck = "({} & ~{})".format(and_out, varibits)
        secondCheck = "(BVXOR({}, {}) & {})".format(
            and_out, rotl(and_out, rot_alpha - rot_beta, wordsize), doublebits)

        command += "ASSERT({} | {} = 0x{});\n".format(
            firstCheck, secondCheck, "0"*(wordsize / 4))

        #Assert XORs
        command += "ASSERT({} = BVXOR({}, BVXOR({}, {})));\n".format(
            x_out, rotl(x_in, rot_gamma, wordsize), y_in, and_out)

        #Weight computation
        command += "ASSERT({0} = (IF {1} = 0x{4} THEN BVSUB({5},0x{4},0x{6}1) \
                  ELSE BVXOR({2}, {3}) ENDIF));\n".format(
                    w, x_in, varibits, doublebits, "f"*(wordsize / 4),
                    wordsize, "0"*((wordsize / 4) - 1))

        stp_file.write(command)
        return

    def getDoubleBits(self, x_in, rot_alpha, rot_beta, wordsize):
        command = "({0} & ~{1} & {2})".format(
            rotl(x_in, rot_beta, wordsize), rotl(x_in, rot_alpha, wordsize),
            rotl(x_in, 2*rot_alpha - rot_beta, wordsize))
        return command
