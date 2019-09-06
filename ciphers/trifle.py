'''
Created on May 6, 2019

@author: hadipour
'''

from parser import stpcommands
from ciphers.cipher import AbstractCipher


class TrifleCipher(AbstractCipher):
    """
    This class can be used to probe differential behavior of trifle cipher under the
    sigle key model. 
    """

    name = "trifle"

    # trifle's Sbox lookup table
    trifle_sbox = [0, 12, 9, 7, 3, 5, 14, 4, 6, 11, 10, 2, 13, 1, 8, 15]

    trifle_sbox_rpos = "(p1 | ~p0) & (~p2 | p0) & (~b3 | p0) & (b3 | b2 | b1 | b0 | ~p1) & (~a0 | p0) & (a3 | a2 | a1 | a0 | ~p0) & (a3 | b2 | b0 | p2 | ~p0) & (~a2 | ~a1 | b2 | ~b1 | p2) & (~a3 | a0 | b2 | ~b0 | p2) & (~a2 | b3 | ~b2 | ~b1 | p2) & (a0 | b3 | ~b2 | b1 | p2) & (a2 | ~a1 | a0 | b3 | b0) & (a1 | ~a0 | b3 | ~b1 | p2) & (~a1 | ~a0 | b1 | ~b0 | p2) & (a3 | ~b3 | ~b1 | ~b0 | p2) & (a3 | a1 | ~a0 | b3 | b2) & (a2 | ~b3 | ~b2 | ~b0 | p2) & (a2 | a1 | b3 | ~b0 | p2) & (~a3 | ~a0 | b1 | b0 | p2) & (~a3 | a2 | a0 | b2 | b1) & (a2 | ~a1 | ~b2 | b0 | p2) & (a3 | ~a2 | ~b3 | b1 | p2) & (a3 | a1 | a0 | b3 | b1 | ~b0) & (~a3 | a1 | b1 | b0 | p2) & (~a1 | a0 | b3 | p2) & (a3 | ~a2 | a1 | b1 | b0) & (~b1 | p0) & (a1 | ~a0 | b3 | ~b2 | b1 | ~p2) & (~a3 | ~a1 | ~a0 | b2 | ~b1 | ~b0) & (~a3 | ~a0 | b3 | ~b2 | ~b1 | ~b0) & (~a3 | ~a2 | a1 | a0 | ~b1 | ~b0) & (~a3 | a1 | ~b3 | b2 | b1 | ~b0) & (a3 | a1 | ~b2 | b1 | b0 | ~p2) & (a1 | ~b3 | ~b1 | b0 | p2) & (~a3 | ~a2 | ~b3 | b2 | ~b1 | ~b0) & (~a2 | ~a1 | ~a0 | ~b2 | ~b1 | b0) & (~a3 | ~a2 | a1 | b2 | ~b1 | b0) & (a2 | ~a1 | a0 | b3 | ~b2 | ~b1) & (a3 | a2 | b3 | b2 | ~b1 | ~b0) & (a1 | a0 | ~b3 | ~b2 | ~b1 | ~b0) & (~a3 | a2 | a1 | ~a0 | ~b2 | ~b1) & (~a3 | a1 | a0 | ~b3 | ~b2 | b1 | ~p2) & (~a3 | ~a2 | ~a1 | ~a0 | ~b3 | ~b2 | ~p2) & (a3 | ~a1 | ~a0 | b3 | ~b2 | ~b1 | ~p2) & (~a3 | ~a2 | a1 | ~a0 | b1 | ~b0 | ~p2) & (~a2 | ~a1 | ~b3 | ~b2 | b1 | ~b0) & (a3 | a2 | ~b3 | ~b2 | ~b1 | ~b0) & (a3 | a2 | ~a1 | ~a0 | ~b3 | ~b2) & (a3 | ~a2 | ~a1 | a0 | ~b3 | ~b0) & (~a2 | ~a1 | a0 | b3 | b1 | ~b0) & (~a2 | ~a1 | a0 | ~b3 | ~b2 | b0 | ~p2) & (a3 | ~a1 | ~a0 | ~b3 | b2 | b0) & (~a3 | a1 | ~a0 | ~b2 | p2) & (~a3 | a2 | ~a1 | b2 | b0 | ~p2) & (~a3 | ~a1 | a0 | b2 | b0 | ~p2) & (a2 | a0 | b2 | b0 | ~p2) & (a3 | ~a2 | ~a0 | b3 | b1 | ~p2) & (a2 | ~a1 | ~a0 | ~b3 | ~b1 | b0) & (~a3 | ~a1 | a0 | ~b2 | p2) & (a1 | b2 | b0 | p2 | ~p0) & (a3 | a1 | ~a0 | b2 | ~b1 | ~b0) & (a2 | a1 | ~a0 | b2 | ~b1 | ~b0 | ~p2) & (a3 | ~a2 | a1 | ~b3 | ~b2 | b0) & (~a3 | a2 | ~a0 | b3 | ~b2 | b1) & (a2 | a0 | b3 | ~b1 | b0 | ~p2) & (a2 | a0 | ~b3 | b2 | b1 | ~p2) & (a3 | a0 | b3 | ~b2 | ~b1 | b0) & (a2 | a1 | ~b3 | b2 | b1 | ~b0) & (a1 | b3 | b1 | b0 | p2 | ~p0) & (~a3 | a2 | a0 | ~b3 | b1 | ~b0) & (~a3 | ~a2 | ~a0 | ~b3 | b1 | ~b0) & (a3 | a1 | b3 | b2 | ~b0 | ~p2)"

    def BP(self, i):
        # Bp stands for BitPermutation
        output = (i / 4) + ((i % 4) * 32)
        return output

    def constraints_by_trifle_sbox(self, variables):
        """
        generate constarints related to sbox
        """
        di = variables[0:4]
        do = variables[4:8]
        w = variables[9:12]
        command = self.trifle_sbox_rpos
        for i in range(4):
            command = command.replace("a%d" % (3 - i), di[i])
            command = command.replace("b%d" % (3 - i), do[i])
            if i <= 2:
                command = command.replace("p%d" % (2 - i), w[i])
        command = "ASSERT(%s = 0bin1);\n" % command
        command += "ASSERT(%s = 0bin0);\n" % variables[8]
        return command

    def getFormatString(self):
        """
        Returns the print format.
        """
        return ['x', 'y', 'w']

    def createSTP(self, stp_filename, parameters):
        """
        Creates an STP file to find a characteristic for trifle with
        the given parameters.
        """

        wordsize = parameters["wordsize"]
        rounds = parameters["rounds"]
        weight = parameters["sweight"]

        if wordsize != 128:
            print("Only wordsize of 128-bit supported.")
            exit(1)

        with open(stp_filename, 'w') as stp_file:
            header = ("% Input File for STP\n% trifle w={} "
                      "rounds={}\n\n\n".format(wordsize, rounds))
            stp_file.write(header)

            # Setup variables
            """            
            x(r) is a variable modeling the 128-bit input difference to the (r+1)'th round
            y(r) is a variable modeling the 128-bit output difference from SubNibbles of the (r+1)'th round            

            Example:
            x0 = x0[127, ..., 0]            
            x0[3:0]     :   nibble 0
            x0[127:124] :   nibble 31                        
            """
            # note that the last integer index in the name of a variable \
            # always shows the round's number in the CryptoSMT
            x = ["x%d" % i for i in range(rounds + 1)]
            y = ["y%d" % i for i in range(rounds)]            
            # w = weight
            w = ["w%d" % i for i in range(rounds)]

            stpcommands.setupVariables(stp_file, x, wordsize)
            stpcommands.setupVariables(stp_file, y, wordsize)            
            stpcommands.setupVariables(stp_file, w, wordsize)
            stpcommands.setupWeightComputation(stp_file, weight, w, wordsize)

            for i in range(rounds):
                self.setupTrifleRound(stp_file, x[i], y[i], x[i+1],
                                      w[i], wordsize)

            # No all zero characteristic
            stpcommands.assertNonZero(stp_file, x, wordsize)

            # Iterative characteristics only
            # Input difference = Output difference
            if parameters["iterative"]:
                stpcommands.assertVariableValue(stp_file, x[0], x[rounds])

            for key, value in parameters["fixedVariables"].items():
                stpcommands.assertVariableValue(stp_file, key, value)

            for char in parameters["blockedCharacteristics"]:
                stpcommands.blockCharacteristic(stp_file, char, wordsize)

            stpcommands.setupQuery(stp_file)

        return

    def setupTrifleRound(self, stp_file, x_in, y, x_out, w, wordsize):
        """
        Model for single key differential behaviour of trifle
        """
        command = ""                       
        
        # SubNibbles
        for i in range(32):
            variables = ["{0}[{1}:{1}]".format(x_in, 4*i + 3),
                         "{0}[{1}:{1}]".format(x_in, 4*i + 2),
                         "{0}[{1}:{1}]".format(x_in, 4*i + 1),
                         "{0}[{1}:{1}]".format(x_in, 4*i + 0),
                         "{0}[{1}:{1}]".format(y, 4*i + 3),
                         "{0}[{1}:{1}]".format(y, 4*i + 2),
                         "{0}[{1}:{1}]".format(y, 4*i + 1),
                         "{0}[{1}:{1}]".format(y, 4*i + 0),
                         "{0}[{1}:{1}]".format(w, 4*i + 3),
                         "{0}[{1}:{1}]".format(w, 4*i + 2),
                         "{0}[{1}:{1}]".format(w, 4*i + 1),
                         "{0}[{1}:{1}]".format(w, 4*i + 0)]            
            #command += stpcommands.add4bitSbox(self.trifle_sbox, variables)
            command += self.constraints_by_trifle_sbox(variables)            
        # BitPermutation Layer
        # zr = PermuteNibbles(xr)
        # zr[i] = xr[PN[i]]
        for i in range(128):
            command += "ASSERT(" + x_out + "[%d:%d]" % (self.BP(i), self.BP(i)) + \
                " = " + y + "[%d:%d]" % (i, i) + ");\n"
        stp_file.write(command)
        return
