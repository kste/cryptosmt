'''
Created on Dec 27, 2016

@author: ralph
'''

from parser import stpcommands
from ciphers.cipher import AbstractCipher


class PresentCipher(AbstractCipher):
    """
    Represents the differential behaviour of PRESENT and can be used
    to find differential characteristics for the given parameters.
    """

    name = "present"

    def getFormatString(self):
        """
        Returns the print format.
        """
        return ['S', 'P', 'w']

    def createSTP(self, stp_filename, parameters):
        """
        Creates an STP file to find a characteristic for PRESENT with
        the given parameters.
        """

        wordsize = parameters["wordsize"]
        rounds = parameters["rounds"]
        weight = parameters["sweight"]

        if wordsize != 64:
            print("Only wordsize of 64-bit supported.")
            exit(1)

        with open(stp_filename, 'w') as stp_file:
            header = ("% Input File for STP\n% PRESENT w={}"
                      "rounds={}\n\n\n".format(wordsize, rounds))
            stp_file.write(header)

            # Setup variables
            s = ["S{}".format(i) for i in range(rounds + 1)]
            p = ["P{}".format(i) for i in range(rounds)]

            # w = weight
            w = ["w{}".format(i) for i in range(rounds)]

            stpcommands.setupVariables(stp_file, s, wordsize)
            stpcommands.setupVariables(stp_file, p, wordsize)
            stpcommands.setupVariables(stp_file, w, wordsize)

            stpcommands.setupWeightComputation(stp_file, weight, w, wordsize)

            for i in range(rounds):
                self.setupPresentRound(stp_file, s[i], p[i], s[i+1], 
                                      w[i], wordsize)

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

    def setupPresentRound(self, stp_file, s_in, p, s_out, w, wordsize):
        """
        Model for differential behaviour of one round PRESENT
        """
        command = ""

        #Permutation Layer
        for i in range(16):
            command += "ASSERT({0}[{1}:{1}] = {2}[{3}:{3}]);\n".format(p, i*4+0, s_out, i)
            command += "ASSERT({0}[{1}:{1}] = {2}[{3}:{3}]);\n".format(p, i*4+1, s_out, i+16)
            command += "ASSERT({0}[{1}:{1}] = {2}[{3}:{3}]);\n".format(p, i*4+2, s_out, i+32)
            command += "ASSERT({0}[{1}:{1}] = {2}[{3}:{3}]);\n".format(p, i*4+3, s_out, i+48)

        # Substitution Layer
        present_sbox = [0xc, 5, 6, 0xb, 9, 0, 0xa, 0xd, 3, 0xe, 0xf, 8, 4, 7, 1, 2]
        for i in range(16):
            variables = ["{0}[{1}:{1}]".format(s_in, 4*i + 3),
                         "{0}[{1}:{1}]".format(s_in, 4*i + 2),
                         "{0}[{1}:{1}]".format(s_in, 4*i + 1),
                         "{0}[{1}:{1}]".format(s_in, 4*i + 0),
                         "{0}[{1}:{1}]".format(p, 4*i + 3),
                         "{0}[{1}:{1}]".format(p, 4*i + 2),
                         "{0}[{1}:{1}]".format(p, 4*i + 1),
                         "{0}[{1}:{1}]".format(p, 4*i + 0),
                         "{0}[{1}:{1}]".format(w, 4*i + 3),
                         "{0}[{1}:{1}]".format(w, 4*i + 2),
                         "{0}[{1}:{1}]".format(w, 4*i + 1),
                         "{0}[{1}:{1}]".format(w, 4*i + 0)]
            command += stpcommands.add4bitSbox(present_sbox, variables)


        stp_file.write(command)
        return
