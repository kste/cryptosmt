'''
Created on Mar 28, 2014

@author: stefan
'''

from parser import stpcommands
from ciphers.cipher import AbstractCipher

from parser.stpcommands import getStringLeftRotate as rotl
from parser.stpcommands import getStringRightRotate as rotr


class SipHashCipher(AbstractCipher):
    """
    Represents the differential behaviour of SipHash and can be used
    to find differential characteristics for the given parameters.
    """

    name = "siphash"
    num_messages = 1

    def getFormatString(self):
        return ['m', 'v0', 'v1', 'v2', 'v3', 'a0', 'a1', 'a2', 'a3',
                'w0', 'w1', 'w2', 'w3', 'weight']

    def createSTP(self, stp_filename, parameters):
        """
        Creates an STP file to find a characteristic for SipHash with
        the given parameters.
        """

        wordsize = parameters["wordsize"]
        rounds = parameters["rounds"]
        weight = parameters["sweight"]
        
        self.num_messages = parameters["nummessages"]

        with open(stp_filename, 'w') as stp_file:
            stp_file.write("% Input File for STP\n% Siphash w={} "
                           "rounds={}\n\n\n".format(wordsize, rounds))

            # Setup variables
            # state = v0, v1, v2, v3
            # intermediate values = a0, a1, a2, a3
            v0 = ["v0{}".format(i) for i in range((rounds + 1) * self.num_messages)]
            v1 = ["v1{}".format(i) for i in range((rounds + 1) * self.num_messages)]
            v2 = ["v2{}".format(i) for i in range((rounds + 1) * self.num_messages)]
            v3 = ["v3{}".format(i) for i in range((rounds + 1) * self.num_messages)]

            a0 = ["a0{}".format(i) for i in range((rounds + 1) * self.num_messages)]
            a1 = ["a1{}".format(i) for i in range((rounds + 1) * self.num_messages)]
            a2 = ["a2{}".format(i) for i in range((rounds + 1) * self.num_messages)]
            a3 = ["a3{}".format(i) for i in range((rounds + 1) * self.num_messages)]

            m = ["m{}".format(i) for i in range(self.num_messages)]

            # w = weight of each modular addition
            w0 = ["w0{}".format(i) for i in range(rounds * self.num_messages)]
            w1 = ["w1{}".format(i) for i in range(rounds * self.num_messages)]
            w2 = ["w2{}".format(i) for i in range(rounds * self.num_messages)]
            w3 = ["w3{}".format(i) for i in range(rounds * self.num_messages)]

            stpcommands.setupVariables(stp_file, v0 + v1 + v2 + v3, wordsize)
            stpcommands.setupVariables(stp_file, a0 + a1 + a2 + a3, wordsize)
            stpcommands.setupVariables(stp_file, w0 + w1 + w2 + w3, wordsize)
            stpcommands.setupVariables(stp_file, m, wordsize)

            stpcommands.setupWeightComputation(stp_file, weight, w0 + w1 + w2 + w3,
                                               wordsize, 1)

            for block in range(self.num_messages):
                self.setupSipBlock(stp_file, block, rounds, m, v0, v1, v2, v3,
                                   a0, a1, a2, a3, w0, w1, w2, w3, wordsize)

            # TODO: There are many different attack scenarios interesting here,
            #       but no interface exists at the moment to support this
            #       without using different "ciphers".

            ## Uncomment to search for internal collision
            # zero_string = "0hex" + "0"*(wordsize / 4)
            # stpcommands.assertVariableValue(stp_file, v0[rounds], zero_string)
            # stpcommands.assertVariableValue(stp_file, v1[rounds], zero_string)
            # stpcommands.assertVariableValue(stp_file, v2[rounds], zero_string)
            # stpcommands.assertVariableValue(stp_file, v3[rounds], zero_string)
            # stpcommands.assertVariableValue(stp_file, v0[0], zero_string)
            # stpcommands.assertVariableValue(stp_file, v1[0], zero_string)
            # stpcommands.assertVariableValue(stp_file, v2[0], zero_string)
            # stpcommands.assertVariableValue(stp_file, v3[0], zero_string)
            # stpcommands.assertNonZero(stp_file, m, wordsize)
            # stp_file.write(self.getStringForCollision(v0[rounds], v1[rounds],
            #                v2[rounds], v3[rounds], wordsize))

            ## Uncomment to search for internal collision for a single block
            # zero_string = "0hex" + "0"*(wordsize / 4)
            # stpcommands.assertVariableValue(stp_file, v0[rounds], zero_string)
            # #stpcommands.assertVariableValue(stp_file, v1[rounds], zero_string)
            # stpcommands.assertVariableValue(stp_file, v2[rounds], zero_string)
            # stpcommands.assertVariableValue(stp_file, v3[rounds], zero_string)
            # stpcommands.assertVariableValue(stp_file, v0[0], zero_string)
            # stpcommands.assertVariableValue(stp_file, v1[0], zero_string)
            # stpcommands.assertVariableValue(stp_file, v2[0], zero_string)
            # stpcommands.assertVariableValue(stp_file, v3[0], v1[rounds])
            # stpcommands.assertVariableValue(stp_file, m[0], zero_string)
            # stpcommands.assertVariableValue(stp_file, m[1], zero_string)
            # stpcommands.assertNonZero(stp_file, [v3[0]], wordsize)
            # stp_file.write(self.getStringForCollision(v0[rounds], v1[rounds],
            #                v2[rounds], v3[rounds], wordsize))

            ## Uncomment to search for Key Collisions
            # stpcommands.assertNonZero(stp_file, [v0[0], v1[0]], wordsize)
            # stpcommands.assertVariableValue(stp_file, v0[0], v3[0])
            # stpcommands.assertVariableValue(stp_file, v1[0], v2[0])
            # stp_file.write(self.getStringForCollision(v0[rounds], v1[rounds],
            #                v2[rounds], v3[rounds], wordsize))

            ## Uncomment to search for message collision
            stpcommands.assertNonZero(stp_file, m, wordsize)
            zero_string = "0hex" + "0"*(wordsize / 4)
            stpcommands.assertVariableValue(stp_file, v0[0], zero_string)
            stpcommands.assertVariableValue(stp_file, v1[0], zero_string)
            stpcommands.assertVariableValue(stp_file, v2[0], zero_string)
            stpcommands.assertVariableValue(stp_file, v3[0], zero_string)
            stp_file.write(self.getStringForCollision(v0[rounds*self.num_messages],
                                                      v1[rounds*self.num_messages],
                                                      v2[rounds*self.num_messages],
                                                      v3[rounds*self.num_messages],
                                                      wordsize))

            ## Uncomment to search for characteristic / distinguisher
            # for i in m:
            #     zero_string = "0hex" + "0"*(wordsize / 4)
            #     stpcommands.assertVariableValue(stp_file, i, zero_string)

            # stpcommands.assertNonZero(stp_file, v0 + v1 + v2 + v3, wordsize)

            for key, value in parameters["fixedVariables"].items():
                stpcommands.assertVariableValue(stp_file, key, value)

            for char in parameters["blockedCharacteristics"]:
                stpcommands.blockCharacteristic(stp_file, char, wordsize)

            stpcommands.setupQuery(stp_file)

        return

    def setupSipBlock(self, stp_file, block, rounds, m, v0, v1, v2, v3,
                      a0, a1, a2, a3, w0, w1, w2, w3, wordsize):
        if rounds == 1:
            rnd = block
            stp_file.write(self.getStringForSipRound(
                v0[rnd], v1[rnd], v2[rnd], "BVXOR({}, {})".format(m[block], v3[rnd]),
                a0[rnd], a1[rnd], a2[rnd], a3[rnd], v0[rnd+1],
                "BVXOR({}, {})".format(m[block], v1[rnd+1]), v2[rnd+1],
                v3[rnd+1], w0[rnd], w1[rnd], w2[rnd], w3[rnd], wordsize))
            return

        for rnd in range(rounds*block, rounds*(block+1)):
            if rnd == rnd*block:
                #Add message block
                stp_file.write(self.getStringForSipRound(
                    v0[rnd], v1[rnd], v2[rnd], "BVXOR({}, {})".format(m[block], v3[rnd]),
                    a0[rnd], a1[rnd], a2[rnd], a3[rnd], v0[rnd+1], v1[rnd+1],
                    v2[rnd+1], v3[rnd+1], w0[rnd], w1[rnd], w2[rnd], w3[rnd], wordsize))
            elif rnd == (rnd*block + (rounds - 1)):
                #Add message block
                stp_file.write(self.getStringForSipRound(
                    v0[rnd], v1[rnd], v2[rnd], v3[rnd], a0[rnd],
                    a1[rnd], a2[rnd], a3[rnd], v0[rnd+1],
                    "BVXOR({}, {})".format(m[block], v1[rnd+1]), v2[rnd+1],
                    v3[rnd+1], w0[rnd], w1[rnd], w2[rnd], w3[rnd], wordsize))
            else:
                stp_file.write(self.getStringForSipRound(
                    v0[rnd], v1[rnd], v2[rnd], v3[rnd], a0[rnd],
                    a1[rnd], a2[rnd], a3[rnd], v0[rnd+1], v1[rnd+1],
                    v2[rnd+1], v3[rnd+1], w0[rnd], w1[rnd], w2[rnd],
                    w3[rnd], wordsize))

    def getStringForCollision(self, v0, v1, v2, v3, wordsize):
        #Collision including the XOR of the message
        command = ""
        command += "ASSERT(0hex{} = BVXOR({}, BVXOR({}, BVXOR({}, {}))));\n".format(
            "0"*(wordsize / 4), v0, v1, v2, v3)
        return command

    def getParamList(self, rounds, wordsize, weight):
        """
        Returns a list of the parameters for SipHash.
        """
        return [wordsize, rounds, weight]

    def getStringForSipRound(self, v0_in, v1_in, v2_in, v3_in, a0, a1, a2, a3,
                             v0_out, v1_out, v2_out, v3_out, w0, w1, w2, w3,
                             wordsize):
        """
        Returns a string representing SipRound in STP.

        a0 = (v1 + v0) <<< 32
        a1 = (v1 + v0) ^ (v1 <<< 13)
        a2 = (v2 + v3)
        a3 = (v2 + v3) ^ (v3 <<< 16)

        v0_out = (a0 + a3)
        v1_out = (a2 + a1) ^ (a1 <<< 17)
        v2_out = (a2 + a1) <<< 32
        v3_out = (a0 + a3) ^ (a3 <<< 21)
        """
        command = ""

        #Assert intermediate values

        #Rotate right to get correct output value
        #a0
        command += "ASSERT("
        command += stpcommands.getStringAdd(
            v1_in, v0_in, rotr(a0, 32, wordsize), wordsize)
        command += ");\n"

        #a1
        command += "ASSERT({} = BVXOR({}, {}));\n".format(
            a1, rotl(v1_in, 13, wordsize), rotr(a0, 32, wordsize))

        #a2
        command += "ASSERT("
        command += stpcommands.getStringAdd(v2_in, v3_in, a2, wordsize)
        command += ");\n"

        #a3
        command += "ASSERT({} = BVXOR({}, {}));\n".format(
            a3, rotl(v3_in, 16, wordsize), a2)

        #v0_out
        command += "ASSERT("
        command += stpcommands.getStringAdd(a0, a3, v0_out, wordsize)
        command += ");\n"

        #v1_out
        command += "ASSERT({} = BVXOR({}, {}));\n".format(
            v1_out, rotl(a1, 17, wordsize), rotr(v2_out, 32, wordsize))

        #v2_out
        command += "ASSERT("
        command += stpcommands.getStringAdd(
            a2, a1, rotr(v2_out, 32, wordsize), wordsize)
        command += ");\n"

        #v3_out
        command += "ASSERT({} = BVXOR({}, {}));\n".format(
            v3_out, rotl(a3, 21, wordsize), v0_out)

        # Lipmaa and Moriai
        command += "ASSERT({0} = ~".format(w0)
        command += stpcommands.getStringEq(
            v1_in, v0_in, rotr(a0, 32, wordsize))
        command += ");\n"

        command += "ASSERT({0} = ~".format(w1)
        command += stpcommands.getStringEq(v2_in, v3_in, a2)
        command += ");\n"

        command += "ASSERT({0} = ~".format(w2)
        command += stpcommands.getStringEq(a0, a3, v0_out)
        command += ");\n"

        command += "ASSERT({0} = ~".format(w3)
        command += stpcommands.getStringEq(
            a2, a1, rotr(v2_out, 32, wordsize))
        command += ");\n"

        return command
