'''
Created on Mar 28, 2014

@author: stefan
'''

from parser import stpcommands
from ciphers.cipher import AbstractCipher

from parser.stpcommands import getStringLeftRotate as rotl
from parser.stpcommands import getStringRightRotate as rotr


class ChasKeyMacHalf(AbstractCipher):
    """
    Represents the ChasKey MAC and can be used
    to find recover a secret key from plaintext/ciphertexts.
    """
    num_messages = 1

    def getName(self):
        """
        Returns the name of the cipher.
        """
        return "chaskeyhalf"

    def getFormatString(self):
        """
        Returns the print format.
        """
        return ['v0', 'v1', 'v2', 'v3', 'w0', 'w1', 'w2', 'w3', 'weight']

    def createSTP(self, stp_filename, cipherParameters):
        """
        Creates an STP file to find a characteristic for ChasKey
        with the given parameters.
        """
        wordsize = cipherParameters[0]
        rounds = cipherParameters[1]
        weight = cipherParameters[2]
        is_iterative = cipherParameters[3]
        fixed_vars = cipherParameters[4]
        chars_blocked = cipherParameters[5]
        self.num_messages = cipherParameters[6]

        with open(stp_filename, 'w') as stp_file:
            stp_file.write("% Input File for STP\n% ChasKeyMac w={} rounds={}"
                           "\n\n\n".format(wordsize, rounds))

            # Setup variables
            # state = v0, v1, v2, v3
            # intermediate values = a0, a1, a2, a3
            v0 = ["v0{}".format(i) for i in range((rounds + 1) * self.num_messages)]
            v1 = ["v1{}".format(i) for i in range((rounds + 1) * self.num_messages)]
            v2 = ["v2{}".format(i) for i in range((rounds + 1) * self.num_messages)]
            v3 = ["v3{}".format(i) for i in range((rounds + 1) * self.num_messages)]

            # w = weight of each modular addition
            w0 = ["w0{}".format(i) for i in range(rounds * self.num_messages)]
            w1 = ["w1{}".format(i) for i in range(rounds * self.num_messages)]

            stpcommands.setupVariables(stp_file, v0, wordsize)
            stpcommands.setupVariables(stp_file, v1, wordsize)
            stpcommands.setupVariables(stp_file, v2, wordsize)
            stpcommands.setupVariables(stp_file, v3, wordsize)
            stpcommands.setupVariables(stp_file, w0, wordsize)
            stpcommands.setupVariables(stp_file, w1, wordsize)

            stpcommands.setupWeightComputation(stp_file, weight, w0 + w1, wordsize, 1)

            #Minimize Weight in middle rounds
            #stpcommands.limitWeight(stp_file, 10, w0[2:4] + w1[2:4], wordsize, 1)

            for i in range(rounds):
                self.setupChasKeyRound(stp_file, i, v0[i], v1[i], v2[i], v3[i],
                                       v0[i + 1], v1[i + 1], v2[i + 1], v3[i + 1],
                                       w0[i], w1[i], wordsize)

            # Message Collision
            stpcommands.assertNonZero(stp_file, v0 + v1 + v2 + v3, wordsize)
            # zeroString = "0hex" + "0"*(wordsize / 4)
            # stpcommands.assertVariableValue(stp_file, v0[rounds], zeroString)
            # stpcommands.assertVariableValue(stp_file, v1[rounds], zeroString)
            # stpcommands.assertVariableValue(stp_file, v2[rounds], zeroString)
            # stpcommands.assertVariableValue(stp_file, v3[rounds], zeroString)

            # Iterative characteristics only
            # Input difference = Output difference
            if is_iterative:
                stpcommands.assertVariableValue(stp_file, v0[0], v0[rounds])
                stpcommands.assertVariableValue(stp_file, v1[0], v1[rounds])
                stpcommands.assertVariableValue(stp_file, v2[0], v2[rounds])
                stpcommands.assertVariableValue(stp_file, v3[0], v3[rounds])

            if fixed_vars:
                for key, value in fixed_vars.iteritems():
                    stpcommands.assertVariableValue(stp_file, key, value)

            if chars_blocked:
                for char in chars_blocked:
                    stpcommands.blockCharacteristic(stp_file, char, wordsize)

            stpcommands.setupQuery(stp_file)

        return

    def setupChasKeyRound(self, stp_file, rnd, v0_in, v1_in, v2_in, v3_in, v0_out,
                          v1_out, v2_out, v3_out, w0, w1, wordsize):

        """
        Half a round of ChasKey

        a0 = (v1 + v0) <<< 32
        a1 = (v1 + v0) ^ (v1 <<< 13)
        a2 = (v2 + v3)
        a3 = (v2 + v3) ^ (v3 <<< 16)
        """
        command = ""

        if (rnd % 2) == 0:
            rotOne = 5
            rotTwo = 8
        else:
            rotOne = 7
            rotTwo = 13

        #Assert intermediate values
        #Rotate right to get correct output value

        #v0_out
        command += "ASSERT("
        command += stpcommands.getStringAdd(v2_in, v3_in, v0_out, wordsize)
        command += ");\n"

        #v1_out
        command += "ASSERT({} = BVXOR({}, {}));\n".format(
            v1_out, rotl(v1_in, rotOne, wordsize), rotr(v2_out, 16, wordsize))

        #v2_out
        command += "ASSERT("
        command += stpcommands.getStringAdd(
            v1_in, v0_in, rotr(v2_out, 16, wordsize), wordsize)
        command += ");\n"

        #v3_out
        command += "ASSERT({} = BVXOR({}, {}));\n".format(
            v3_out, rotl(v3_in, rotTwo, wordsize), v0_out)

        # Compute Weights for modular addition
        # Lipmaa and Moriai

        command += "ASSERT({0} = ~".format(w0)
        command += stpcommands.getStringEq(
            v1_in, v0_in, rotr(v2_out, 16, wordsize), wordsize)
        command += ");\n"

        command += "ASSERT({0} = ~".format(w1)
        command += stpcommands.getStringEq(v2_in, v3_in, v0_out, wordsize)
        command += ");\n"

        stp_file.write(command)
        return

    def getParamList(self, rounds, wordsize, weight):
        """
        Returns a list of the parameters for ChasKey.
        """
        return [wordsize, rounds, weight]
