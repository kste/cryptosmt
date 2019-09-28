'''
Created on Apr 3, 2017

@author: ralph
'''

from parser import stpcommands
from ciphers.cipher import AbstractCipher

from parser.stpcommands import getStringRightRotate as rotr
from parser.stpcommands import getStringLeftRotate as rotl

class NoekeonCipher(AbstractCipher):
    """
    Represents the differential behaviour of NOEKEON and can be used
    to find differential characteristics for the given parameters.
    """

    name = "noekeon"

    def getFormatString(self):
        """
        Returns the print format.
        """
        return ['A0', 'A1', 'A2', 'A3', 'w']

    def createSTP(self, stp_filename, parameters):
        """
        Creates an STP file to find a characteristic for NOEKEON with
        the given parameters.
        """

        wordsize = parameters["wordsize"]
        rounds = parameters["rounds"]
        weight = parameters["sweight"]

        with open(stp_filename, 'w') as stp_file:
            header = ("% Input File for STP\n% NOEKEON w={}"
                      "rounds={}\n\n\n".format(wordsize,rounds))
            stp_file.write(header)

            # Setup variables
            #
            a0 = ["A0{}".format(i) for i in range(rounds + 1)]
            a1 = ["A1{}".format(i) for i in range(rounds + 1)]
            a2 = ["A2{}".format(i) for i in range(rounds + 1)]
            a3 = ["A3{}".format(i) for i in range(rounds + 1)]

            theta0 = ["T0{}".format(i) for i in range(rounds)]
            theta1 = ["T1{}".format(i) for i in range(rounds)]
            theta2 = ["T2{}".format(i) for i in range(rounds)]
            theta3 = ["T3{}".format(i) for i in range(rounds)]

            pi10 = ["PI10{}".format(i) for i in range(rounds)]
            pi11 = ["PI11{}".format(i) for i in range(rounds)]
            pi12 = ["PI12{}".format(i) for i in range(rounds)]
            pi13 = ["PI13{}".format(i) for i in range(rounds)]

            gamma0 = ["G0{}".format(i) for i in range(rounds)]
            gamma1 = ["G1{}".format(i) for i in range(rounds)]
            gamma2 = ["G2{}".format(i) for i in range(rounds)]
            gamma3 = ["G3{}".format(i) for i in range(rounds)]

            pi20 = ["PI20{}".format(i) for i in range(rounds)]
            pi21 = ["PI21{}".format(i) for i in range(rounds)]
            pi22 = ["PI22{}".format(i) for i in range(rounds)]
            pi23 = ["PI23{}".format(i) for i in range(rounds)]

            # w = weight
            w = ["w{}".format(i) for i in range(rounds)]

            stpcommands.setupVariables(stp_file, a0, wordsize)
            stpcommands.setupVariables(stp_file, a1, wordsize)
            stpcommands.setupVariables(stp_file, a2, wordsize)
            stpcommands.setupVariables(stp_file, a3, wordsize)

            stpcommands.setupVariables(stp_file, theta0, wordsize)
            stpcommands.setupVariables(stp_file, theta1, wordsize)
            stpcommands.setupVariables(stp_file, theta2, wordsize)
            stpcommands.setupVariables(stp_file, theta3, wordsize)

            stpcommands.setupVariables(stp_file, pi10, wordsize)
            stpcommands.setupVariables(stp_file, pi11, wordsize)
            stpcommands.setupVariables(stp_file, pi12, wordsize)
            stpcommands.setupVariables(stp_file, pi13, wordsize)

            stpcommands.setupVariables(stp_file, pi20, wordsize)
            stpcommands.setupVariables(stp_file, pi21, wordsize)
            stpcommands.setupVariables(stp_file, pi22, wordsize)
            stpcommands.setupVariables(stp_file, pi23, wordsize)

            stpcommands.setupVariables(stp_file, gamma0, wordsize)
            stpcommands.setupVariables(stp_file, gamma1, wordsize)
            stpcommands.setupVariables(stp_file, gamma2, wordsize)
            stpcommands.setupVariables(stp_file, gamma3, wordsize)
            stpcommands.setupVariables(stp_file, w, wordsize*4)

            stpcommands.setupWeightComputation(stp_file, weight, w, wordsize*4)

            for i in range(rounds):
                self.setupNoekeonRound(stp_file,
                          a0[i], a1[i], a2[i], a3[i],
                          theta0[i], theta1[i], theta2[i], theta3[i],
                          gamma0[i], gamma1[i], gamma2[i], gamma3[i],
                          pi10[i], pi11[i], pi12[i], pi13[i],
                          pi20[i], pi21[i], pi22[i], pi23[i],
                          a0[i+1], a1[i+1], a2[i+1], a3[i+1],
                          w[i], wordsize)

            # No all zero characteristic
            stpcommands.assertNonZero(stp_file, a0+a1+a2+a3, wordsize)

            # Iterative characteristics only
            # Input difference = Output difference
            if parameters["iterative"]:
                stpcommands.assertVariableValue(stp_file, a0[0], a0[rounds])
                stpcommands.assertVariableValue(stp_file, a1[0], a1[rounds])
                stpcommands.assertVariableValue(stp_file, a2[0], a2[rounds])
                stpcommands.assertVariableValue(stp_file, a3[0], a3[rounds])

            for key, value in parameters["fixedVariables"].items():
                stpcommands.assertVariableValue(stp_file, key, value)

            for char in parameters["blockedCharacteristics"]:
                stpcommands.blockCharacteristic(stp_file, char, wordsize)

            stpcommands.setupQuery(stp_file)

        return

    def setupNoekeonRound(self, stp_file,
                          a0_in, a1_in, a2_in, a3_in,
                          theta0, theta1, theta2, theta3,
                          gamma0, gamma1, gamma2, gamma3,
                          pi10, pi11, pi12, pi13,
                          pi20, pi21, pi22, pi23,
                          a0_out, a1_out, a2_out, a3_out,
                          w, wordsize):
        """
        Model for differential behaviour of one round NOEKEON
        """
        command = ""

        command += self.theta(a0_in, a1_in, a2_in, a3_in, theta0, theta1, theta2, theta3, wordsize)
        command += self.pi1(theta0, theta1, theta2, theta3, pi10, pi11, pi12, pi13, wordsize)
        command += self.gamma(pi10, pi11, pi12, pi13, gamma0, gamma1, gamma2, gamma3, w)
        command += self.pi2(gamma0, gamma1, gamma2, gamma3, a0_out, a1_out, a2_out, a3_out, wordsize)

        stp_file.write(command)
        return

    def theta(self, in0, in1, in2, in3, out0, out1, out2, out3, wordsize):
        """
        Model for the Theta function in NOEKEON
        """
        command = ""

        in1xorin3 = "BVXOR({0}[31:0], {1}[31:0])".format(in1, in3)
        in1xorin3lr = rotl(in1xorin3, 8, wordsize)
        in1xorin3rr = rotr(in1xorin3, 8, wordsize)
        l = "BVXOR({0}, BVXOR({1}, {2}))".format(in1xorin3lr, in1xorin3, in1xorin3rr)

        in0xorin2 = "BVXOR({0}[31:0], {1}[31:0])".format(in0, in2)
        in0xorin2lr = rotl(in0xorin2, 8, wordsize)
        in0xorin2rr = rotr(in0xorin2, 8, wordsize)
        r = "BVXOR({0}, BVXOR({1}, {2}))".format(in0xorin2lr, in0xorin2, in0xorin2rr)

        command += "ASSERT({0}[31:0] = BVXOR({1}[31:0], {2}[31:0]));\n".format(out0, in0, l)
        command += "ASSERT({0}[31:0] = BVXOR({1}[31:0], {2}[31:0]));\n".format(out1, in1, r)
        command += "ASSERT({0}[31:0] = BVXOR({1}[31:0], {2}[31:0]));\n".format(out2, in2, l)
        command += "ASSERT({0}[31:0] = BVXOR({1}[31:0], {2}[31:0]));\n".format(out3, in3, r)

        return command

    def gamma(self, in0, in1, in2, in3, out0, out1, out2, out3, w):
        """
        Model for the Gamma function in NOEKEON - represents the Sbox layer
        """
        command = ""

        noekeon_sbox = [7, 0xA, 2, 0xC, 4, 8, 0xF, 0, 5, 9, 1, 0xE, 3, 0xD, 0xB, 6]
        for i in range(32):
            variables = ["{0}[{1}:{1}]".format(in3, i),
                         "{0}[{1}:{1}]".format(in2, i),
                         "{0}[{1}:{1}]".format(in1, i),
                         "{0}[{1}:{1}]".format(in0, i),
                         "{0}[{1}:{1}]".format(out3, i),
                         "{0}[{1}:{1}]".format(out2, i),
                         "{0}[{1}:{1}]".format(out1, i),
                         "{0}[{1}:{1}]".format(out0, i),
                         "{0}[{1}:{1}]".format(w, 4*i + 3),
                         "{0}[{1}:{1}]".format(w, 4*i + 2),
                         "{0}[{1}:{1}]".format(w, 4*i + 1),
                         "{0}[{1}:{1}]".format(w, 4*i + 0)]
            command += stpcommands.add4bitSbox(noekeon_sbox, variables)
        # for i in range(8):
        #     variables = ["{0}[{1}:{1}]".format(in0, 4*i + 3),
        #                  "{0}[{1}:{1}]".format(in0, 4*i + 2),
        #                  "{0}[{1}:{1}]".format(in0, 4*i + 1),
        #                  "{0}[{1}:{1}]".format(in0, 4*i + 0),
        #                  "{0}[{1}:{1}]".format(out0, 4*i + 3),
        #                  "{0}[{1}:{1}]".format(out0, 4*i + 2),
        #                  "{0}[{1}:{1}]".format(out0, 4*i + 1),
        #                  "{0}[{1}:{1}]".format(out0, 4*i + 0),
        #                  "{0}[{1}:{1}]".format(w, 4*i + 3),
        #                  "{0}[{1}:{1}]".format(w, 4*i + 2),
        #                  "{0}[{1}:{1}]".format(w, 4*i + 1),
        #                  "{0}[{1}:{1}]".format(w, 4*i + 0)]
        #     command += stpcommands.add4bitSbox(noekeon_sbox, variables)
        #
        # for i in range(8):
        #     variables = ["{0}[{1}:{1}]".format(in1, 4*i + 3),
        #                  "{0}[{1}:{1}]".format(in1, 4*i + 2),
        #                  "{0}[{1}:{1}]".format(in1, 4*i + 1),
        #                  "{0}[{1}:{1}]".format(in1, 4*i + 0),
        #                  "{0}[{1}:{1}]".format(out1, 4*i + 3),
        #                  "{0}[{1}:{1}]".format(out1, 4*i + 2),
        #                  "{0}[{1}:{1}]".format(out1, 4*i + 1),
        #                  "{0}[{1}:{1}]".format(out1, 4*i + 0),
        #                  "{0}[{1}:{1}]".format(w, 4*i + 3 + 32),
        #                  "{0}[{1}:{1}]".format(w, 4*i + 2 + 32),
        #                  "{0}[{1}:{1}]".format(w, 4*i + 1 + 32),
        #                  "{0}[{1}:{1}]".format(w, 4*i + 0 + 32)]
        #     command += stpcommands.add4bitSbox(noekeon_sbox, variables)
        #
        # for i in range(8):
        #     variables = ["{0}[{1}:{1}]".format(in2, 4*i + 3),
        #                  "{0}[{1}:{1}]".format(in2, 4*i + 2),
        #                  "{0}[{1}:{1}]".format(in2, 4*i + 1),
        #                  "{0}[{1}:{1}]".format(in2, 4*i + 0),
        #                  "{0}[{1}:{1}]".format(out2, 4*i + 3),
        #                  "{0}[{1}:{1}]".format(out2, 4*i + 2),
        #                  "{0}[{1}:{1}]".format(out2, 4*i + 1),
        #                  "{0}[{1}:{1}]".format(out2, 4*i + 0),
        #                  "{0}[{1}:{1}]".format(w, 4*i + 3 + 64),
        #                  "{0}[{1}:{1}]".format(w, 4*i + 2 + 64),
        #                  "{0}[{1}:{1}]".format(w, 4*i + 1 + 64),
        #                  "{0}[{1}:{1}]".format(w, 4*i + 0 + 64)]
        #     command += stpcommands.add4bitSbox(noekeon_sbox, variables)
        #
        # for i in range(8):
        #     variables = ["{0}[{1}:{1}]".format(in3, 4*i + 3),
        #                  "{0}[{1}:{1}]".format(in3, 4*i + 2),
        #                  "{0}[{1}:{1}]".format(in3, 4*i + 1),
        #                  "{0}[{1}:{1}]".format(in3, 4*i + 0),
        #                  "{0}[{1}:{1}]".format(out3, 4*i + 3),
        #                  "{0}[{1}:{1}]".format(out3, 4*i + 2),
        #                  "{0}[{1}:{1}]".format(out3, 4*i + 1),
        #                  "{0}[{1}:{1}]".format(out3, 4*i + 0),
        #                  "{0}[{1}:{1}]".format(w, 4*i + 3 + 96),
        #                  "{0}[{1}:{1}]".format(w, 4*i + 2 + 96),
        #                  "{0}[{1}:{1}]".format(w, 4*i + 1 + 96),
        #                  "{0}[{1}:{1}]".format(w, 4*i + 0 + 96)]
        #     command += stpcommands.add4bitSbox(noekeon_sbox, variables)

        return command

    def pi1(self, in0, in1, in2, in3, out0, out1, out2, out3, wordsize):
        """
        Model for the Pi1 function in NOEKEON - which is the inverse of pi2
        """
        command = ""

        command += "ASSERT({0}[31:0] = {1}[31:0]);\n".format(in0, out0)
        command += "ASSERT({0}[31:0] = {1}[31:0]);\n".format(rotl(in1, 1, wordsize), out1)
        command += "ASSERT({0}[31:0] = {1}[31:0]);\n".format(rotl(in2, 5, wordsize), out2)
        command += "ASSERT({0}[31:0] = {1}[31:0]);\n".format(rotl(in3, 2, wordsize), out3)

        return command


    def pi2(self, in0, in1, in2, in3, out0, out1, out2, out3, wordsize):
        """
        Model for the Pi2 function in NOEKEON - which is the inverse of pi1
        """
        command = ""

        command += "ASSERT({0}[31:0] = {1}[31:0]);\n".format(in0, out0)
        command += "ASSERT({0}[31:0] = {1}[31:0]);\n".format(rotr(in1, 1, wordsize), out1)
        command += "ASSERT({0}[31:0] = {1}[31:0]);\n".format(rotr(in2, 5, wordsize), out2)
        command += "ASSERT({0}[31:0] = {1}[31:0]);\n".format(rotr(in3, 2, wordsize), out3)

        return command
