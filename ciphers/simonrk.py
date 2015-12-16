'''
Created on Mar 28, 2014

@author: stefan
'''

from parser import stpcommands
from ciphers.cipher import AbstractCipher

from parser.stpcommands import getStringLeftRotate as rotl
from parser.stpcommands import getStringRightRotate as rotr


class SimonRkCipher(AbstractCipher):
    """
    Represents the differential behaviour of SIMON in the related key
    attack scenario and can be used to find differential characteristics
    for the given parameters.
    """

    name = "simonrk"
    rot_alpha = 8
    rot_beta = 1
    rot_gamma = 2


    def getFormatString(self):
        """
        Returns the print format.
        """
        return ['x', 'y', 'k', 'w']

    def createSTP(self, stp_filename, parameters):
        """
        Creates an STP file to find a characteristic for SIMON in the
        related-key scenario with the given parameters.
        """

        wordsize = parameters["wordsize"]
        rounds = parameters["rounds"]
        weight = parameters["sweight"]

        # Replace with custom if set in parameters.
        if "rotationconstants" in parameters:
            self.rot_alpha = parameters["rotationconstants"][0] 
            self.rot_beta = parameters["rotationconstants"][1]
            self.rot_gamma = parameters["rotationconstants"][2]

        with open(stp_filename, 'w') as stp_file:
            header = ("% Input File for STP\n% Simon w={} alpha={} beta={}"
                      " gamma={} rounds={}\n\n\n".format(wordsize,
                                                         self.rot_alpha,
                                                         self.rot_beta,
                                                         self.rot_gamma,
                                                         rounds))
            stp_file.write(header)

            # Setup variable
            # x = left, y = right
            x = ["x{}".format(i) for i in range(rounds + 1)]
            y = ["y{}".format(i) for i in range(rounds + 1)]
            k = ["k{}".format(i) for i in range(rounds)]
            and_out = ["andout{}".format(i) for i in range(rounds + 1)]

            # w = weight
            w = ["w{}".format(i) for i in range(rounds)]

            stpcommands.setupVariables(stp_file, x, wordsize)
            stpcommands.setupVariables(stp_file, y, wordsize)
            stpcommands.setupVariables(stp_file, k, wordsize)
            stpcommands.setupVariables(stp_file, and_out, wordsize)
            stpcommands.setupVariables(stp_file, w, wordsize)

            stpcommands.setupWeightComputation(stp_file, weight, w, wordsize)

            #Key Schedule
            self.setupSimonKey(stp_file, k, rounds, wordsize)

            for i in range(rounds):
                self.setupSimonRound(stp_file, x[i], y[i], k[i], x[i+1], y[i+1],
                                     and_out[i], w[i], wordsize)

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

    def setupSimonKey(self, stp_file, k, rounds, wordsize):
        command = ""
        for i in range(4, rounds):
            tmpZ = "BVXOR({}, {})".format(rotr(k[i - 1], 3, wordsize), k[i - 3])
            command += "ASSERT({} = ".format(k[i])
            command += "BVXOR({}, ".format(tmpZ)
            command += "BVXOR({}, ".format(rotr(tmpZ, 1, wordsize))
            command += "BVXOR({}, ~{}".format(k[i - 3], k[i - 4])
            command += "))));\n"
        stp_file.write(command)
        return

    def setupSimonRound(self, stp_file, x_in, y_in, key, x_out, y_out, and_out,
                        w, wordsize):
        """
        Model for differential behaviour of one round SIMON
        y[i+1] = x[i]
        x[i+1] = (x[i] <<< 1) & (x[i] <<< 8) ^ y[i] ^ (x[i] << 2) ^ k
        """
        command = ""

        #Assert(y_out = x_in)
        command += "ASSERT({} = {});\n".format(y_out, x_in)

        x_in_rotalpha = rotl(x_in, self.rot_alpha, wordsize)
        x_in_rotbeta = rotl(x_in, self.rot_beta, wordsize)

        #Deal with dependent inputs
        varibits = "({0} | {1})".format(x_in_rotalpha, x_in_rotbeta)
        doublebits = self.getDoubleBits(x_in, wordsize)

        #Check for valid difference
        firstcheck = "({} & ~{})".format(and_out, varibits)
        secondcheck = "(BVXOR({}, {}) & {})".format(
            and_out, rotl(and_out, self.rot_alpha - self.rot_beta, wordsize), doublebits)
        thirdcheck = "(IF {0} = 0x{1} THEN BVMOD({2}, {0}, 0x{3}2) ELSE 0x{4} ENDIF)".format(
            x_in, "f" * (wordsize // 4), wordsize, "0" * (wordsize // 4 - 1), 
            "0" * (wordsize // 4))

        command += "ASSERT(({} | {} | {}) = 0x{});\n".format(
            firstcheck, secondcheck, thirdcheck, "0" * (wordsize // 4))

        #Assert XORs
        command += "ASSERT({} = BVXOR({}, BVXOR({}, BVXOR({}, {}))));\n".format(
            key, x_out, rotl(x_in, self.rot_gamma, wordsize), y_in, and_out)

        #Weight computation
        command += "ASSERT({0} = (IF {1} = 0x{4} THEN BVSUB({5},0x{4},0x{6}1) \
                  ELSE BVXOR({2}, {3}) ENDIF));\n".format(
                    w, x_in, varibits, doublebits, "f"*(wordsize // 4),
                    wordsize, "0"*((wordsize // 4) - 1))
        stp_file.write(command)
        return

    def getDoubleBits(self, x_in, wordsize):
        command = "({0} & ~{1} & {2})".format(
            rotl(x_in, self.rot_beta, wordsize), rotl(x_in, self.rot_alpha, wordsize),
            rotl(x_in, 2*self.rot_alpha - self.rot_beta, wordsize))
        return command
