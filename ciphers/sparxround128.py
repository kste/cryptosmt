'''
Created on May 29, 2017

@author: ralph
'''

from parser import stpcommands
from ciphers.cipher import AbstractCipher

from parser.stpcommands import getStringRightRotate as rotr
from parser.stpcommands import getStringLeftRotate as rotl

class SPARXRound128Cipher(AbstractCipher):
    """
    Represents the differential behaviour of SPARX-128 and can be used
    to find differential characteristics for the given parameters.
    """

    name = "sparxround128"
    rounds_per_step = 4

    def getFormatString(self):
        """
        Returns the print format.
        """
        return ['X0L', 'X0R', 'X1L', 'X1R', 'X2L','X2R', 'X3L', 'X3R', 
                'LX0L', 'LX0R', 'LX1L', 'LX1R', 'wx0','wx1', 'wx2', 'wx3']

    def createSTP(self, stp_filename, parameters):
        """
        Creates an STP file to find a characteristic for SPARX with
        the given parameters.
        """

        wordsize = parameters["wordsize"]
        rounds = parameters["rounds"]
        weight = parameters["sweight"]

        with open(stp_filename, 'w') as stp_file:
            header = ("% Input File for STP\n% SPARX w={}"
                      "rounds={}\n\n\n".format(wordsize,rounds))
            stp_file.write(header)

            # Setup variables
            x0l = ["X0L{}".format(i) for i in range(rounds + 1)]
            x0r = ["X0R{}".format(i) for i in range(rounds + 1)]
            x1l = ["X1L{}".format(i) for i in range(rounds + 1)]
            x1r = ["X1R{}".format(i) for i in range(rounds + 1)]
            x2l = ["X2L{}".format(i) for i in range(rounds + 1)]
            x2r = ["X2R{}".format(i) for i in range(rounds + 1)]
            x3l = ["X3L{}".format(i) for i in range(rounds + 1)]
            x3r = ["X3R{}".format(i) for i in range(rounds + 1)]

            x0l_after_A = ["X0LA{}".format(i) for i in range(rounds + 1)]
            x0r_after_A = ["X0RA{}".format(i) for i in range(rounds + 1)]
            x1l_after_A = ["X1LA{}".format(i) for i in range(rounds + 1)]
            x1r_after_A = ["X1RA{}".format(i) for i in range(rounds + 1)]
            x2l_after_A = ["X2LA{}".format(i) for i in range(rounds + 1)]
            x2r_after_A = ["X2RA{}".format(i) for i in range(rounds + 1)]
            x3l_after_A = ["X3LA{}".format(i) for i in range(rounds + 1)]
            x3r_after_A = ["X3RA{}".format(i) for i in range(rounds + 1)]

            x0l_after_L = ["LX0L{}".format(i) for i in range(rounds + 1)]
            x0r_after_L = ["LX0R{}".format(i) for i in range(rounds + 1)]
            x1l_after_L = ["LX1L{}".format(i) for i in range(rounds + 1)]
            x1r_after_L = ["LX1R{}".format(i) for i in range(rounds + 1)]

            # w = weight
            wx0 = ["wx0{}".format(i) for i in range(rounds)]
            wx1 = ["wx1{}".format(i) for i in range(rounds)]
            wx2 = ["wx2{}".format(i) for i in range(rounds)]
            wx3 = ["wx3{}".format(i) for i in range(rounds)]

            stpcommands.setupVariables(stp_file, x0l, wordsize)
            stpcommands.setupVariables(stp_file, x0r, wordsize)
            stpcommands.setupVariables(stp_file, x1l, wordsize)
            stpcommands.setupVariables(stp_file, x1r, wordsize)
            stpcommands.setupVariables(stp_file, x2l, wordsize)
            stpcommands.setupVariables(stp_file, x2r, wordsize)
            stpcommands.setupVariables(stp_file, x3l, wordsize)
            stpcommands.setupVariables(stp_file, x3r, wordsize)

            stpcommands.setupVariables(stp_file, x0l_after_A, wordsize)
            stpcommands.setupVariables(stp_file, x0r_after_A, wordsize)
            stpcommands.setupVariables(stp_file, x1l_after_A, wordsize)
            stpcommands.setupVariables(stp_file, x1r_after_A, wordsize)
            stpcommands.setupVariables(stp_file, x2l_after_A, wordsize)
            stpcommands.setupVariables(stp_file, x2r_after_A, wordsize)
            stpcommands.setupVariables(stp_file, x3l_after_A, wordsize)
            stpcommands.setupVariables(stp_file, x3r_after_A, wordsize)

            stpcommands.setupVariables(stp_file, x0l_after_L, wordsize)
            stpcommands.setupVariables(stp_file, x0r_after_L, wordsize)
            stpcommands.setupVariables(stp_file, x1l_after_L, wordsize)
            stpcommands.setupVariables(stp_file, x1r_after_L, wordsize)

            stpcommands.setupVariables(stp_file, wx0, wordsize)
            stpcommands.setupVariables(stp_file, wx1, wordsize)
            stpcommands.setupVariables(stp_file, wx2, wordsize)
            stpcommands.setupVariables(stp_file, wx3, wordsize)

            # Ignore MSB
            stpcommands.setupWeightComputation(stp_file, weight, wx0 + wx1 + wx2 + wx3, wordsize, 1)

            for i in range(rounds):
                if ((i+1) % self.rounds_per_step) == 0:
                    #do round function (SPECKEY)
                    self.setupSPECKEYRound(stp_file, x0l[i], x0r[i],
                                           x0l_after_A[i], x0r_after_A[i],
                                           wx0[i], wordsize)
                    #do round function (SPECKEY)
                    self.setupSPECKEYRound(stp_file, x1l[i], x1r[i],
                                           x1l_after_A[i], x1r_after_A[i],
                                           wx1[i], wordsize)
                    #do round function (SPECKEY)
                    self.setupSPECKEYRound(stp_file, x2l[i], x2r[i],
                                           x2l_after_A[i], x2r_after_A[i],
                                           wx2[i], wordsize)
                    #do round function (SPECKEY)
                    self.setupSPECKEYRound(stp_file, x3l[i], x3r[i],
                                           x3l_after_A[i], x3r_after_A[i],
                                           wx3[i], wordsize)

                    #every step do L-box and feistel
                    self.setupSPARXRound(stp_file,
                                         x0l_after_A[i], x0r_after_A[i],
                                         x1l_after_A[i], x1r_after_A[i],
                                         x2l_after_A[i], x2r_after_A[i],
                                         x3l_after_A[i], x3r_after_A[i],
                                         x0l_after_L[i], x0r_after_L[i],
                                         x1l_after_L[i], x1r_after_L[i],
                                         x0l[i+1], x0r[i+1],
                                         x1l[i+1], x1r[i+1],
                                         x2l[i+1], x2r[i+1],
                                         x3l[i+1], x3r[i+1])
                else:
                    #do round function (SPECKEY)
                    self.setupSPECKEYRound(stp_file, x0l[i], x0r[i], x0l[i+1], x0r[i+1],
                                           wx0[i], wordsize)
                    #do round function (SPECKEY)
                    self.setupSPECKEYRound(stp_file, x1l[i], x1r[i], x1l[i+1], x1r[i+1],
                                           wx1[i], wordsize)
                    #do round function (SPECKEY)
                    self.setupSPECKEYRound(stp_file, x2l[i], x2r[i], x2l[i+1], x2r[i+1],
                                           wx2[i], wordsize)
                    #do round function (SPECKEY)
                    self.setupSPECKEYRound(stp_file, x3l[i], x3r[i], x3l[i+1], x3r[i+1],
                                           wx3[i], wordsize)

            # No all zero characteristic
            stpcommands.assertNonZero(stp_file, x0l+x0r+x1l+x1r+x2l+x2r+x3l+x3r, wordsize)

            # Iterative characteristics only
            # Input difference = Output difference
            if parameters["iterative"]:
                stpcommands.assertVariableValue(stp_file, x0l[0], x0l[rounds])
                stpcommands.assertVariableValue(stp_file, x0r[0], x0r[rounds])
                stpcommands.assertVariableValue(stp_file, x1l[0], x1l[rounds])
                stpcommands.assertVariableValue(stp_file, x1r[0], x1r[rounds])
                stpcommands.assertVariableValue(stp_file, x2l[0], x2l[rounds])
                stpcommands.assertVariableValue(stp_file, x2r[0], x2r[rounds])
                stpcommands.assertVariableValue(stp_file, x3l[0], x3l[rounds])
                stpcommands.assertVariableValue(stp_file, x3r[0], x3r[rounds])

            for key, value in parameters["fixedVariables"].items():
                stpcommands.assertVariableValue(stp_file, key, value)

            for char in parameters["blockedCharacteristics"]:
                stpcommands.blockCharacteristic(stp_file, char, wordsize)

            stpcommands.setupQuery(stp_file)

        return

    def setupSPARXRound(self, stp_file, x0l_in, x0r_in,
                                        x1l_in, x1r_in,
                                        x2l_in, x2r_in,
                                        x3l_in, x3r_in,
                                        x0l_after_L, x0r_after_L,
                                        x1l_after_L, x1r_after_L,
                                        x0l_out, x0r_out,
                                        x1l_out, x1r_out,
                                        x2l_out, x2r_out,
                                        x3l_out, x3r_out,):
        """
        Model for differential behaviour of one step SPARX
        """
        command = ""
        command += self.L(x0l_in, x0r_in, x1l_in, x1r_in,
                          x0l_after_L, x0r_after_L, x1l_after_L, x1r_after_L)

        #Assert(x_out = L(A^a(x_in)) xor A^a(y_in))
        command += "ASSERT(" + x0l_out + " = "
        command += "BVXOR(" + x0l_after_L + " , " + x2l_in + ")"
        command += ");\n"
        command += "ASSERT(" + x0r_out + " = "
        command += "BVXOR(" + x0r_after_L + " , " + x2r_in + ")"
        command += ");\n"
        command += "ASSERT(" + x1l_out + " = "
        command += "BVXOR(" + x1l_after_L + " , " + x3l_in + ")"
        command += ");\n"
        command += "ASSERT(" + x1r_out + " = "
        command += "BVXOR(" + x1r_after_L + " , " + x3r_in + ")"
        command += ");\n"

        #Assert(y_out = A^a(x_in))
        command += "ASSERT({} = {});\n".format(x2l_out, x0l_in)
        command += "ASSERT({} = {});\n".format(x2r_out, x0r_in)
        command += "ASSERT({} = {});\n".format(x3l_out, x1l_in)
        command += "ASSERT({} = {});\n".format(x3r_out, x1r_in)

        stp_file.write(command)
        return


    def setupSPECKEYRound(self, stp_file, x_in, y_in, x_out, y_out, w, wordsize):
        """
        Model for the ARX box (round) function of SPARX which is the
        same as SPECKEY.
        """
        command = ""

        #Assert((x_in >>> 7) + y_in = x_out)
        command += "ASSERT("
        command += stpcommands.getStringAdd(rotr(x_in, 7, wordsize),
                                            y_in, x_out, wordsize)
        command += ");\n"

        #Assert(x_out xor (y_in <<< 2) = y_out)
        command += "ASSERT(" + y_out + " = "
        command += "BVXOR(" + x_out + ","
        command += rotl(y_in, 2, wordsize)
        command += "));\n"

        #For weight computation
        command += "ASSERT({0} = ~".format(w)
        command += stpcommands.getStringEq(rotr(x_in, 7, wordsize),
                                           y_in, x_out)
        command += ");\n"

        stp_file.write(command)
        return

    def L(self, x0l_in, x0r_in, x1l_in, x1r_in, x0l_out, x0r_out, x1l_out, x1r_out):
        """
        Model for the L' function in SPARX-128. L' is the Feistel function
        """
        command = ""

        # (x_in xor y_in)
        xor_x0 = "BVXOR(" + x0l_in + " , " + x0r_in + ")"
        xor_x1 = "BVXOR(" + x1l_in + " , " + x1r_in + ")"
        xor_x0_x1 = "BVXOR(" + xor_x0 + " , " + xor_x1 + ")"
        #(x_in xor y_in) <<< 8)
        rot_x0_x1 = rotl(xor_x0_x1, 8, 16)

        # exchange x0l_out and x1l_out
        command += "ASSERT(" + x1l_out + " = "
        command += "BVXOR(" + x0l_in + " , " + rot_x0_x1 + "));\n"
        command += "ASSERT(" + x0r_out + " = "
        command += "BVXOR(" + x0r_in + " , " + rot_x0_x1 + "));\n"
        command += "ASSERT(" + x0l_out + " = "
        command += "BVXOR(" + x1l_in + " , " + rot_x0_x1 + "));\n"
        command += "ASSERT(" + x1r_out + " = "
        command += "BVXOR(" + x1r_in + " , " + rot_x0_x1 + "));\n"

        return command
