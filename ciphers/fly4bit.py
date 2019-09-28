'''
Created on Apr 10, 2017

@author: ralph
'''

from parser import stpcommands
from ciphers.cipher import AbstractCipher


class Fly4BitCipher(AbstractCipher):
    """
    Represents the differential behaviour of Fly and can be used
    to find differential characteristics for the given parameters.
    """

    name = "fly4bit"

    def getFormatString(self):
        """
        Returns the print format.
        """
        return ['S', 'P', 'w']

    def createSTP(self, stp_filename, parameters):
        """
        Creates an STP file to find a characteristic for FLY with
        the given parameters.
        """

        wordsize = parameters["wordsize"]
        rounds = parameters["rounds"]
        weight = parameters["sweight"]

        if wordsize != 64:
            print("Only wordsize of 64-bit supported.")
            exit(1)

        with open(stp_filename, 'w') as stp_file:
            header = ("% Input File for STP\n% FLY w={}"
                      "rounds={}\n\n\n".format(wordsize, rounds))
            stp_file.write(header)

            # Setup variables
            s = ["S{}".format(i) for i in range(rounds + 1)]
            sbox1 = ["SB{}".format(i) for i in range(rounds)]
            p = ["P{}".format(i) for i in range(rounds)]

            # w = weight
            w = ["w{}".format(i) for i in range(3*rounds)]

            stpcommands.setupVariables(stp_file, s, wordsize)
            stpcommands.setupVariables(stp_file, sbox1, int(wordsize/2))
            stpcommands.setupVariables(stp_file, p, wordsize)
            stpcommands.setupVariables(stp_file, w, wordsize)

            stpcommands.setupWeightComputation(stp_file, weight, w, wordsize)

            for i in range(rounds):
                self.setupFlyRound(stp_file, s[i], p[i], sbox1[i], s[i+1], w[i], w[i+rounds], w[i+(2*rounds)], wordsize)

            # No all zero characteristic
            stpcommands.assertNonZero(stp_file, s, wordsize)

            # Iterative characteristics only
            # Input difference = Output difference
            if parameters["iterative"]:
                stpcommands.assertVariableValue(stp_file, s[0], s[rounds])

            for key, value in parameters["fixedVariables"].items():
                stpcommands.assertVariableValue(stp_file, key, value)

            for char in parameters["blockedCharacteristics"]:
                stpcommands.blockCharacteristic(stp_file, char, wordsize)

            stpcommands.setupQuery(stp_file)

        return

    def setupFlyRound(self, stp_file, s_in, p, sbox1, s_out, w1, w2, w3, wordsize):
        """
        Model for differential behaviour of one round FLY
        """
        command = ""

        # Substitution Layer
        fly_sbox = [0, 0xa, 4, 0xf, 0xc, 7, 2, 8, 0xd, 0xe, 9 , 0xb, 5, 6, 3, 1]

        for i in range(8):
            hixorlo = "BVXOR({0}[{1}:{2}], {0}[{3}:{4}])".format(s_in, 8*i+3, 8*i+0, 8*i+7, 8*i+4)

            #Sbox 1 - center
            variables = ["{0}[{1}:{1}]".format(hixorlo, 4*i + 3),
                         "{0}[{1}:{1}]".format(hixorlo, 4*i + 2),
                         "{0}[{1}:{1}]".format(hixorlo, 4*i + 1),
                         "{0}[{1}:{1}]".format(hixorlo, 4*i + 0),
                         "{0}[{1}:{1}]".format(sbox1, 4*i + 3),
                         "{0}[{1}:{1}]".format(sbox1, 4*i + 2),
                         "{0}[{1}:{1}]".format(sbox1, 4*i + 1),
                         "{0}[{1}:{1}]".format(sbox1, 4*i + 0),
                         "{0}[{1}:{1}]".format(w1, 4*i + 3),
                         "{0}[{1}:{1}]".format(w1, 4*i + 2),
                         "{0}[{1}:{1}]".format(w1, 4*i + 1),
                         "{0}[{1}:{1}]".format(w1, 4*i + 0)]
            command += stpcommands.add4bitSbox(fly_sbox, variables)

            #sbox2 = "BVXOR({0}[{2}:{3}], {1}[{4}:{5}])".format(s_in, sbox1, 8*i+3, 8*i+0, 4*i + 3, 4*i + 0)
            #sbox3 = "BVXOR({0}[{2}:{3}], {1}[{4}:{5}])".format(s_in, sbox1, 8*i+7, 8*i+4, 4*i + 3, 4*i + 0)

            command += "ASSERT({6}[{2}:{3}] = BVXOR({0}[{2}:{3}], {1}[{4}:{5}]));\n".format(s_in, sbox1, 8*i+3, 8*i+0, 4*i + 3, 4*i + 0, p)
            command += "ASSERT({6}[{2}:{3}] = BVXOR({0}[{2}:{3}], {1}[{4}:{5}]));\n".format(s_in, sbox1, 8*i+7, 8*i+4, 4*i + 3, 4*i + 0, p)

            """
            #Sbox 2 - left
            variables = ["{0}[{1}:{1}]".format(sbox2, 4*i + 3),
                         "{0}[{1}:{1}]".format(sbox2, 4*i + 2),
                         "{0}[{1}:{1}]".format(sbox2, 4*i + 1),
                         "{0}[{1}:{1}]".format(sbox2, 4*i + 0),
                         "{0}[{1}:{1}]".format(p, 8*i + 3),
                         "{0}[{1}:{1}]".format(p, 8*i + 2),
                         "{0}[{1}:{1}]".format(p, 8*i + 1),
                         "{0}[{1}:{1}]".format(p, 8*i + 0),
                         "{0}[{1}:{1}]".format(w2, 4*i + 3),
                         "{0}[{1}:{1}]".format(w2, 4*i + 2),
                         "{0}[{1}:{1}]".format(w2, 4*i + 1),
                         "{0}[{1}:{1}]".format(w2, 4*i + 0)]
            command += stpcommands.add4bitSbox(fly_sbox, variables)


            #Sbox 3 - right
            variables = ["{0}[{1}:{1}]".format(sbox3, 4*i + 3),
                         "{0}[{1}:{1}]".format(sbox3, 4*i + 2),
                         "{0}[{1}:{1}]".format(sbox3, 4*i + 1),
                         "{0}[{1}:{1}]".format(sbox3, 4*i + 0),
                         "{0}[{1}:{1}]".format(p, 8*i + 7),
                         "{0}[{1}:{1}]".format(p, 8*i + 6),
                         "{0}[{1}:{1}]".format(p, 8*i + 5),
                         "{0}[{1}:{1}]".format(p, 8*i + 4),
                         "{0}[{1}:{1}]".format(w3, 4*i + 3),
                         "{0}[{1}:{1}]".format(w3, 4*i + 2),
                         "{0}[{1}:{1}]".format(w3, 4*i + 1),
                         "{0}[{1}:{1}]".format(w3, 4*i + 0)]
            command += stpcommands.add4bitSbox(fly_sbox, variables)
            """

        #Permutation Layer
        #Rot(.) = (i+8*(i mod 8)) mod 64
        for i in range(64):
            command += "ASSERT({0}[{1}:{1}] = {2}[{3}:{3}]);\n".format(p, i, s_out, (i+8*(i%8))%64)

        stp_file.write(command)
        return
