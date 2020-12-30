'''
Created on  May 27, 2019

@author: Hosein Hadipour
'''

from parser import stpcommands
from ciphers.cipher import AbstractCipher

class CraftCipherLinear(AbstractCipher):
    """
    This class can be used to investigate the security of CRAFT against the 
    linear cryptanalysis in the single tweak model. 
    """

    name = "craftlinear"

    # CRAFTS's Sbox lookup table
    craft_sbox = [0xc, 0xa, 0xd, 0x3, 0xe, 0xb, 0xf,
                  0x7, 0x8, 0x9, 0x1, 0x5, 0x0, 0x2, 0x4, 0x6]
    # CRAFTS's PermuteNibble lookup table
    PN = [0xf, 0xc, 0xd, 0xe, 0xa, 0x9, 0x8, 0xb,
          0x6, 0x5, 0x4, 0x7, 0x1, 0x2, 0x3, 0x0]
    # Reduced product of sum (POS) representation of LAT^2 for craft's sbox
    # Each entry of LAT^2 is the square of the corresponding entry in LAT
    # LAT^2 (square of LAT) can be considered as a boolean function like this f(di, do, corr^2) = b in {0, 1}
    # for example f(0x0, 0x0, 0x0) = 1
    craft_sbox_rpos = "(~p3 | p2) & (p1 | ~p0) & (p3 | ~p2) & (~p2 | p0) & (~b1 | p0) & (b3 | b2 | b1 | b0 | ~p1) & (~b3 | p0) & (a3 | a2 | a1 | a0 | ~p0) & (a3 | a1 | b3 | ~b0 | p2) & (a1 | a0 | ~b2 | b1 | p2) & (~a1 | p0) & (a3 | b3 | ~b2 | b1 | ~b0) & (~a3 | ~a1 | b2 | b1 | p2) & (a0 | b2 | ~b1 | ~b0 | p2) & (~a3 | ~a0 | ~b3 | b0 | p2) & (a0 | ~b3 | ~b2 | ~b1 | p2) & (~a0 | b2 | b1 | b0 | p2) & (a2 | ~a0 | ~b3 | ~b1 | p2) & (a2 | a1 | b1 | ~b0 | p2) & (~a3 | p0) & (a3 | ~a1 | b2 | ~b1 | b0 | p2) & (a3 | ~a1 | ~a0 | ~b2 | b1 | p2) & (~a3 | ~a1 | b3 | b0 | p2) & (a2 | ~a1 | b3 | ~b1 | b0 | p2) & (a3 | ~a2 | ~a0 | ~p2) & (a2 | a0 | ~b2 | ~b1 | p2) & (a3 | ~a2 | ~a1 | b1 | ~b0 | p2) & (~a3 | ~a2 | a0 | b2 | b0 | p2) & (~a3 | a1 | ~a0 | ~b2 | ~b1 | p2) & (a3 | a1 | b3 | ~b2 | p2) & (a3 | ~b3 | ~b2 | b0 | ~p2) & (~a2 | ~a0 | b2 | b0 | ~p2) & (~a3 | a2 | ~a0 | b3 | ~p2) & (~a3 | ~a2 | a0 | b3 | ~p2) & (~a3 | ~a1 | ~b3 | b1 | p2) & (~a3 | ~b3 | b2 | ~b0 | p2) & (~a2 | b2 | b1 | b0 | p2) & (a3 | ~b3 | b2 | ~b0 | ~p2) & (a2 | a0 | b2 | b0 | ~p2) & (~a2 | ~a0 | ~b2 | ~b0 | ~p2) & (a2 | a0 | ~b2 | ~b0 | ~p2) & (a3 | ~a2 | a0 | b3 | ~b2 | b0 | p2) & (b3 | b2 | b0 | ~p2) & (~a3 | ~a2 | ~a1 | ~a0 | b3 | ~b1 | p2) & (~a2 | a1 | ~a0 | b3 | b1 | p2) & (a2 | ~a1 | ~a0 | b3 | b2 | p2) & (b3 | ~b2 | ~b0 | ~p2) & (a3 | ~a2 | ~a0 | b1) & (~a2 | a1 | b3 | ~b1 | ~b0 | p2) & (a3 | a2 | a0 | ~p2) & (a1 | a0 | ~b3 | ~b1 | p2) & (a3 | ~a2 | ~a1 | ~a0 | ~b2 | ~b0) & (a3 | ~a2 | ~a0 | b3 | b2 | b0) & (~a3 | a2 | ~a0 | ~b1 | b0 | p2) & (a2 | a0 | ~b3 | ~b2 | b0 | p2) & (~a1 | a0 | ~b3 | b2 | ~b0 | p2)"

    def constraints_by_craft_sbox(self, variables):
        """
        generate constarints related to sbox
        """

        di = variables[0:4]
        do = variables[4:8]
        w = variables[8:12]
        command = self.craft_sbox_rpos
        for i in range(4):
            command = command.replace("a%d" % (3 - i), di[i])
            command = command.replace("b%d" % (3 - i), do[i])        
            command = command.replace("p%d" % (3 - i), w[i])
        command = "ASSERT(%s = 0bin1);\n" % command        
        return command

    def getFormatString(self):
        """
        Returns the print format.
        """

        return ['x', 'y', 'z', 'w']

    def createSTP(self, stp_filename, parameters):
        """
        Creates an STP file to find a characteristic for CRAFT with
        the given parameters.
        """

        wordsize = parameters["wordsize"]
        rounds = parameters["rounds"]
        weight = parameters["sweight"]

        if wordsize != 64:
            print("Only wordsize of 64-bit supported.")
            exit(1)

        with open(stp_filename, 'w') as stp_file:
            header = ("% Input File for STP\n% CRAFT w={} "
                      "rounds={}\n\n\n".format(wordsize, rounds))
            stp_file.write(header)

            # Setup variables
            """
            x(roundNumber), other variables are like this one. 
            x(r) is a variable modeling the 64-bit input difference to the (r+1)'th round
            y(r) is a variable modeling the 64-bit output difference from MixColumn of the (r+1)'th round
            z(r) is a variable modeling the 64-bit output difference from PermuteNibble of the (r+1)'th round
            x(r+1) is a variable modeling the 64-bit output differenece from the (r+1)'th round
            Example:
            x0 = x0[63, 62, ..., 0]            
            x0[3:0]:     nibble 0
            x0[63:60]:   nibble 15
            It is supposed that the input difference is as bellow:
            [x[3:0], x[7:4], ..., x[63:60]]            
            """

            # note that the last integer index in the name of a variable \
            # always shows the round's number in the CryptoSMT
            x = ["x%d" % i for i in range(rounds + 1)]
            y = ["y%d" % i for i in range(rounds)]
            z = ["z%d" % i for i in range(rounds)]
            # w = weight
            w = ["w%d" % i for i in range(rounds)]

            stpcommands.setupVariables(stp_file, x, wordsize)
            stpcommands.setupVariables(stp_file, y, wordsize)
            stpcommands.setupVariables(stp_file, z, wordsize)
            stpcommands.setupVariables(stp_file, w, wordsize)
            stpcommands.setupWeightComputation(stp_file, weight, w, wordsize)

            for i in range(rounds):
                self.setupCraftRound(stp_file, x[i], y[i], z[i], x[i+1],
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

    def setupCraftRound(self, stp_file, x_in, y, z, x_out, w, wordsize):
        """
        Model for single tweak differential behaviour of CRAFT
        """

        command = ""
        """
        MixColumn
        note that in CVC language when you use x[i:j], i must always be equal or greater than j
        I' = MC(I)
        I[i, j] = I[4*i + j]
        I[0] = nibble 0
        I[15] = nibble 15
        I'[j] = I[j] for j = [0, 7]
        I'[8 + j] = I[8 + j] xor I[j] for j = [0, 3]
        I'[12 + j] = I[12 + j] xor I[4 + j] xor I[j] for j = [0, 3]
        I[j] = xr[4*j + 3:4*j]
        I'[j] = yr[4*j + 3:4j]
        """
        command += "ASSERT(" + y + "[32:0]" + \
            " = " + x_in + "[32:0]" + ");\n"
        for j in range(4):
            command += "ASSERT(" + y + \
                "[%d:%d]" % (4*(8 + j) + 3, 4*(8 + j)) + " = "
            command += "BVXOR(" + x_in + "[%d:%d]" % (4*(8 + j) + 3, 4*(8 + j)) +\
                "," + x_in + "[%d:%d]" % (4*j + 3, 4*j) + "));\n" 
            command += "ASSERT(" + y + "[%d:%d]" % (4*(12+ j) + 3, 4*(12 + j)) + " = "
            command += "BVXOR("
            command += "BVXOR(" + x_in + "[%d:%d]" % (4*(12 + j) + 3, 4*(12 + j)) +\
                "," + x_in + "[%d:%d]" % (4*(4 + j) + 3, 4*(4 + j)) + "),"
            command += x_in + "[%d:%d]" % (4*j + 3, 4*j) + "));\n"
                          
        # PermuteNibbles Layer
        # zr = PermuteNibbles(xr)
        # zr[i] = xr[PN[i]]
        for i in range(16):
            command += "ASSERT(" + z + "[%d:%d]" % (4*i + 3, 4*i) + \
                " = " + y + "[%d:%d]" % (4*self.PN[i] + 3,
                                         4*self.PN[i]) + ");\n"
        # Sbox layer
        for i in range(16):
            variables = ["{0}[{1}:{1}]".format(z, 4*i + 3),
                         "{0}[{1}:{1}]".format(z, 4*i + 2),
                         "{0}[{1}:{1}]".format(z, 4*i + 1),
                         "{0}[{1}:{1}]".format(z, 4*i + 0),
                         "{0}[{1}:{1}]".format(x_out, 4*i + 3),
                         "{0}[{1}:{1}]".format(x_out, 4*i + 2),
                         "{0}[{1}:{1}]".format(x_out, 4*i + 1),
                         "{0}[{1}:{1}]".format(x_out, 4*i + 0),                        
                         "{0}[{1}:{1}]".format(w, 4*i + 3),
                         "{0}[{1}:{1}]".format(w, 4*i + 2),
                         "{0}[{1}:{1}]".format(w, 4*i + 1),
                         "{0}[{1}:{1}]".format(w, 4*i + 0)]
            # print(variables)
            # command += stpcommands.add4bitSbox(self.craft_sbox, variables)
            command += self.constraints_by_craft_sbox(variables)

        stp_file.write(command)
        return
