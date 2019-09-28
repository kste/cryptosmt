'''
Created on April 24, 2019

@author: hadipour
'''

from parser import stpcommands
from ciphers.cipher import AbstractCipher

class CraftCipher(AbstractCipher):
    """
    This class can be used to probe differential behavior of CRAFT cipher under
    sigle tweak model. In other words it can be used to find the best single tweak
    differential trail for the given rounds. It also can be used to estimate the 
    differential effect for the given rounds.
    """

    name = "craft"

    # CRAFTS's Sbox lookup table
    craft_sbox = [0xc, 0xa, 0xd, 0x3, 0xe, 0xb, 0xf,
                  0x7, 0x8, 0x9, 0x1, 0x5, 0x0, 0x2, 0x4, 0x6]
    # CRAFTS's PermuteNibble lookup table
    PN = [0xf, 0xc, 0xd, 0xe, 0xa, 0x9, 0x8, 0xb,
          0x6, 0x5, 0x4, 0x7, 0x1, 0x2, 0x3, 0x0]
    # reduced product of sum representation of ddt of craft's sbox
    # ddt is considered as a boolean function like this ddt(di, do, p) = b in {0, 1}
    # for example ddt(0, 0, 0) = 1
    craft_sbox_rpos = "(~a1 | a0 | b2 | ~b1 | ~p2) & (a2 | ~a1 | ~b1 | b0 | ~p2) & (a3 | a2 | a1 | ~b3 | ~b0) & (~a3 | ~a0 | b3 | b2 | b1) & (a3 | a1 | a0 | ~b3 | ~b2) & (~a3 | ~a2 | b3 | b1 | b0) & (a2 | ~a1 | b2 | ~b1 | ~p2) & (~a1 | a0 | ~b1 | b0 | ~p2) & (~a2 | ~a0 | ~b2 | ~b0 | ~p2) & (a1 | ~b3 | ~b2 | ~b0) & (~a3 | ~a2 | ~a0 | b1) & (p1 | ~p0) & (~p2 | p0) & (~b1 | p0) & (a2 | ~a0 | b1 | p2) & (a1 | ~b2 | b0 | p2) & (~b3 | p0) & (b2 | ~b1 | b0 | ~p2) & (a1 | b1 | ~b0 | p2) & (~a2 | a0 | b1 | p2) & (~a3 | b1 | b0 | p2) & (~a2 | ~a0 | b3 | b0 | p2) & (~a1 | p0) & (a2 | a0 | b2 | b1 | b0 | ~p1) & (a2 | a1 | a0 | p2 | ~p0) & (~a2 | a0 | ~b2 | ~b0 | p2) & (a1 | b2 | ~b0 | p2) & (a2 | a0 | ~b2 | ~b0 | ~p2) & (~a2 | ~a0 | b2 | ~b0 | p2) & (~a3 | a0 | b2 | ~b0 | p2) & (a3 | ~a1 | ~b3 | ~b1 | p2) & (a2 | ~a0 | ~b2 | ~b0 | p2) & (~a1 | b3 | ~b2 | ~b1 | ~b0 | p2) & (a2 | ~a1 | b3 | b2 | ~b1) & (~a1 | a0 | b3 | ~b2 | b1 | ~p2) & (a2 | ~a1 | b3 | b1 | ~b0 | ~p2) & (a1 | ~b2 | ~b1 | ~b0 | ~p2) & (b3 | b2 | b0 | ~p2) & (a3 | a2 | a0 | ~p2) & (~a2 | ~a1 | ~a0 | b1 | ~p2) & (~a3 | a2 | ~a0 | ~b2 | ~b1 | b0) & (a2 | a0 | ~b2 | ~b1 | b0 | p2) & (~a2 | ~a1 | a0 | b3 | b0) & (~a2 | a0 | ~b3 | b2 | p2) & (a2 | ~a0 | ~b3 | b0 | p2) & (~a1 | a0 | ~b3 | b2 | ~b0 | ~p2) & (a2 | ~a1 | ~b3 | ~b2 | b0 | ~p2) & (~a0 | ~b3 | ~b2 | b0 | p2) & (a3 | ~a2 | a1 | ~b1 | b0 | ~p2) & (a3 | a1 | ~a0 | b2 | ~b1 | ~p2) & (~a2 | ~a0 | b2 | b1 | b0) & (a3 | a2 | ~b2 | ~b0 | p2) & (~a3 | ~a2 | a1 | a0 | b3 | b2 | ~p2) & (a3 | a1 | a0 | ~b3 | b1 | ~b0) & (a3 | a2 | a1 | ~b3 | ~b2 | b1) & (~a3 | a1 | ~a0 | b3 | b1 | b0) & (~a3 | ~a2 | a0 | b2 | ~b1 | ~b0)"    

    def constraints_by_craft_sbox(self, variables):
        """
        generate constarints related to sbox
        """
        di = variables[0:4]
        do = variables[4:8]        
        w = variables[9:12]        
        command = self.craft_sbox_rpos
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
            stpcommands.assertNonZero(stp_file, [x[0]], wordsize)

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
        I'[j] = I[j] xor I[j + 8] xor I[12 + j] for j = [0, 3]
        I'[4 + j] = I[4 + j] xor I[12 + j] for j = [0, 3]
        I'[8 + j] = I[8 + j] for j = [0, 7]        
        I[j] = xr[4*j + 3:4*j]
        I'[j] = yr[4*j + 3:4j]
        """
        for j in range(4):
            command += "ASSERT(" + y + "[%d:%d]" % (4*j + 3, 4*j) + " = "
            command += "BVXOR("
            command += "BVXOR(" + x_in + "[%d:%d]" % (4*(8 + j) + 3, 4*(8 + j)) +\
                "," + x_in + "[%d:%d]" % (4*(12 + j) + 3, 4*(12 + j)) + "),"
            command += x_in + "[%d:%d]" % (4*j + 3, 4*j) + "));\n"
            command += "ASSERT(" + y + \
                "[%d:%d]" % (4*(4 + j) + 3, 4*(4 + j)) + " = "
            command += "BVXOR(" + x_in + "[%d:%d]" % (4*(4 + j) + 3, 4*(4 + j)) +\
                "," + x_in + "[%d:%d]" % (4*(12 + j) + 3, 4*(12 + j)) + "));\n"
        command += "ASSERT(" + y + "[63:32]" + \
            " = " + x_in + "[63:32]" + ");\n"

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
            #command += stpcommands.add4bitSbox(self.craft_sbox, variables)        
            command += self.constraints_by_craft_sbox(variables)
        stp_file.write(command)
        return
