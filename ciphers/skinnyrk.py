'''
Created on Oct 22, 2017

@author: stefan, ralph

Revised on Jan 6, 2020 by Hosein Hadipour
'''

from parser import stpcommands
from ciphers.cipher import AbstractCipher


class SkinnyRKCipher(AbstractCipher):
    """
    Represents the differential behaviour of Skinny in the related tweakey setting and can be used
    to find differential characteristics for the given parameters.
    """

    name = "skinnyrk"
    # Sbox lookup table   
    skinny_sbox = [0xc, 0x6, 0x9, 0x0, 0x1, 0xa, 0x2, 0xb,  
                    0x3, 0x8, 0x5, 0xd, 0x4, 0xe, 0x7, 0xf]
    # reduced product of sum representation of ddt
    skinny_sbox_rpos = "(~a1 | a0 | ~b3 | ~b2 | b1 | b0) & (~a1 | a0 | ~b3 | ~b2 | ~b1 | ~b0) & (~a2 | ~a1 | ~a0 | ~b2 | b1 | ~b0) & (~a2 | ~a1 | ~a0 | ~b2 | ~b1 | b0) & (p1 | ~p0) & (~b0 | p0) & (a1 | b2 | ~p2) & (~b2 | p0) & (~a2 | ~b2 | p2) & (~a1 | b3 | b2 | b0) & (a2 | b3 | ~p2) & (a3 | a2 | a0 | ~b3) & (~a0 | p0) & (~a1 | ~b3 | p2) & (~a3 | ~b3 | ~b1 | p2) & (~a2 | p0) & (a3 | a2 | a1 | ~b2) & (a2 | a1 | b3 | ~b1) & (a1 | b3 | b2 | b1 | ~p1) & (~a2 | b3 | ~b0 | p2) & (~a3 | a0 | b2 | ~b0 | p2) & (~a1 | b1 | b0 | p2) & (~a3 | a2 | ~b3 | p2) & (~a3 | p0) & (~a1 | ~a0 | ~b2 | p2) & (b3 | ~b2 | b1 | ~b0 | ~p2) & (~a3 | ~a2 | a1 | b1 | ~p2) & (a3 | a0 | ~b3 | b0 | p2) & (a3 | ~a1 | a0 | ~b3 | b2 | ~b0) & (~a3 | ~a0 | ~b3 | b2 | ~b0 | ~p2) & (a2 | ~a1 | a0 | ~b2 | ~p2) & (a3 | a1 | ~b3 | ~b1 | ~p2) & (~a3 | ~a2 | a0 | b2 | b0 | ~p2) & (a3 | ~a2 | ~a0 | b2 | b0 | ~p2) & (~a2 | ~a0 | b1 | b0 | p2) & (a3 | ~a2 | ~a0 | ~b0 | p2) & (~a3 | a2 | ~a0 | b2 | ~p2) & (a3 | ~a0 | b3 | ~b0 | p2) & (~a1 | b3 | ~b1 | b0 | ~p2) & (a1 | b3 | b1 | ~p2) & (~b2 | ~b1 | ~b0 | p2) & (a0 | ~b3 | b1 | ~b0 | p2)"
    # Tweakey schedule permutation
    tk_permutation = [9, 15, 8, 13, 10, 14, 12, 11, 0, 1, 2, 3, 4, 5, 6, 7]

    def constraints_by_skinny_sbox(self, variables):
        """
        Generate constraints related to sbox
        """
        di = variables[0:4]
        do = variables[4:8]
        w = variables[9:12]
        command = self.skinny_sbox_rpos
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
        state = ['x', 'atk', 'y', 'z']
        tk = ['tk{}'.format(i) for i in range(3)]
        weight = ['w']
        # return state
        return state + tk + weight

    def createSTP(self, stp_filename, parameters):
        """
        Creates an STP file to find a characteristic for Skinny64rk with
        the given parameters.
        """

        blocksize = parameters["blocksize"]
        wordsize = parameters["wordsize"]
        keysize = parameters["keysize"]
        tweaksize = parameters["tweaksize"]
        rounds = parameters["rounds"]
        weight = parameters["sweight"]

        if blocksize != 64:
            print("Only blocksize of 64-bit supported.")
            exit(1)

        if (keysize + tweaksize) % 64 != 0:
            print("Tweakeysize must be a multiple of 64-bits")
            exit(1)

        # calculate the number of Tweakey words
        # // -> integer division
        nrOfTK = (keysize + tweaksize) // 64        

        with open(stp_filename, 'w') as stp_file:
            header = ("% Input File for STP\n% Skinny w={}"
                      "rounds={}\n\n\n".format(blocksize, rounds))
            stp_file.write(header)

            # Setup variables
            # sc = ["SC{}".format(i) for i in range(rounds + 1)]
            # atk = ["ATK{}".format(i) for i in range(rounds)]
            # sr = ["SR{}".format(i) for i in range(rounds)]
            # mc = ["MC{}".format(i) for i in range(rounds)]
            # tk = ["TK{}{}".format(i, j) for j in range(rounds) for i in range(nrOfTK)]
            # tk_after_pt = ["TKP{}{}".format(i, j) for j in range(rounds) for i in range(nrOfTK)]
            
            sc = ["x{}".format(i) for i in range(rounds + 1)]
            atk = ["atk{}".format(i) for i in range(rounds)]
            sr = ["y{}".format(i) for i in range(rounds)]
            mc = ["z{}".format(i) for i in range(rounds)]
            tk = ["tk{}{}".format(i, j) for i in range(nrOfTK) for j in range(rounds)]
            tk_after_pt = ["ptk{}{}".format(i, j) for j in range(nrOfTK) for i in range(rounds)]

            # w = weight
            w = ["w{}".format(i) for i in range(rounds)]

            stpcommands.setupVariables(stp_file, sc, blocksize)
            stpcommands.setupVariables(stp_file, atk, blocksize)
            stpcommands.setupVariables(stp_file, sr, blocksize)
            stpcommands.setupVariables(stp_file, mc, blocksize)
            stpcommands.setupVariables(stp_file, tk, blocksize)
            stpcommands.setupVariables(stp_file, tk_after_pt, blocksize)
            stpcommands.setupVariables(stp_file, w, blocksize)

            stpcommands.setupWeightComputation(stp_file, weight, w, blocksize)

            self.setupTweakeySchedule(stp_file, tk, tk_after_pt, rounds, blocksize, nrOfTK)

            for i in range(rounds):
                if nrOfTK == 1:
                    self.setupSkinnyRound(stp_file, sc[i], atk[i], sr[i], mc[i], sc[i+1], 
                                          w[i], blocksize, nrOfTK,  tk[i])
                if nrOfTK == 2:
                    self.setupSkinnyRound(stp_file, sc[i], atk[i], sr[i], mc[i], sc[i+1], 
                                          w[i], blocksize, nrOfTK, tk[i], tk[i+(rounds)])
                if nrOfTK == 3:
                    self.setupSkinnyRound(stp_file, sc[i], atk[i], sr[i], mc[i], sc[i+1], 
                                          w[i], blocksize, nrOfTK, tk[i], tk[i+(rounds)], tk[i+(2*rounds)])

            # No all zero characteristic
            stpcommands.assertNonZero(stp_file, sc, blocksize)

            # Iterative characteristics only
            # Input difference = Output difference
            if parameters["iterative"]:
                stpcommands.assertVariableValue(stp_file, sc[0], sc[rounds])

            for key, value in parameters["fixedVariables"].items():
                stpcommands.assertVariableValue(stp_file, key, value)

            for char in parameters["blockedCharacteristics"]:
                stpcommands.blockCharacteristic(stp_file, char, blocksize)

            stpcommands.setupQuery(stp_file)

        return

    def setupTweakeySchedule(self, stp_file, tk, tk_after_pt, rounds, blocksize, nrOfTK):
        """
        Model for the TWEAKEY schedule used in SKINNY
        """
        command = ""

        for r in range(1, rounds):
            # Apply permuation P_t to all tweakey words            
            for i in range(nrOfTK):  # for each tweakey word
                for nibble in range(16):
                    command += "ASSERT({1}[{3}:{2}] = {0}[{5}:{4}]);\n".format(tk[(r-1)+(rounds*i)],
                                                                               tk_after_pt[(r-1)+(rounds*i)],
                                                                               nibble*4,
                                                                               (nibble*4)+3,
                                                                               self.tk_permutation[nibble]*4,
                                                                               (self.tk_permutation[nibble]*4)+3)            
            command += "ASSERT({}[63:0] = {}[63:0]);\n".format(tk_after_pt[(r-1)+(rounds*0)], tk[r+(rounds*0)])
            # Apply LFSRs to tweakey words TK-2 and TK3

            #TK-2
            #(x3||x2||x1||x0) -> (x2||x1||x0||x3\oplusx2)
            #x0 = lsb of the cell
            if (nrOfTK > 1):
                for nibble in range(8): # apply LFSR's only to row 0,1
                    command += "ASSERT({0}[{2}:{2}] = {1}[{3}:{3}]);\n".format(tk_after_pt[(r-1)+(rounds*1)],
                                                                               tk[r+(rounds*1)],
                                                                               (nibble*4)+2,
                                                                               (nibble*4)+3)   #x2->x3
                    command += "ASSERT({0}[{2}:{2}] = {1}[{3}:{3}]);\n".format(tk_after_pt[(r-1)+(rounds*1)],
                                                                              tk[r+(rounds*1)],
                                                                               (nibble*4)+1,
                                                                               (nibble*4)+2)   #x1->x2
                    command += "ASSERT({0}[{2}:{2}] = {1}[{3}:{3}]);\n".format(tk_after_pt[(r-1)+(rounds*1)],
                                                                               tk[r+(rounds*1)],
                                                                               (nibble*4)+0,
                                                                               (nibble*4)+1)   #x0->x1
                    command += "ASSERT(BVXOR({0}[{3}:{3}], {1}[{4}:{4}]) = {2}[{5}:{5}]);\n".format(tk_after_pt[(r-1)+(rounds*1)],
                                                                                                    tk_after_pt[(r-1)+(rounds*1)],
                                                                                                    tk[r+(rounds*1)],
                                                                                                    (nibble*4)+3,
                                                                                                    (nibble*4)+2,
                                                                                                    (nibble*4)+0)   #x3 \oplus x2 -> x0
                command += "ASSERT({}[63:32] = {}[63:32]);\n".format(tk_after_pt[(r-1)+(rounds*1)], tk[r+(rounds*1)])
            #TK-3
            #(x3||x2||x1||x0) -> (x0 \oplus x3||x3||x2||x1)
            #x0 = lsb of the cell
            if (nrOfTK > 2):
                for nibble in range(8): # apply LFSR's only to row 0,1
                    command += "ASSERT(BVXOR({0}[{3}:{3}], {1}[{4}:{4}]) = {2}[{5}:{5}]);\n".format(tk_after_pt[(r-1)+(rounds*2)],
                                                                                                    tk_after_pt[(r-1)+(rounds*2)],
                                                                                                    tk[r+(rounds*2)],
                                                                                                    (nibble*4)+0,
                                                                                                    (nibble*4)+3,
                                                                                                    (nibble*4)+3)   #x0 \oplus x3 -> x3
                    command += "ASSERT({0}[{2}:{2}] = {1}[{3}:{3}]);\n".format(tk_after_pt[(r-1)+(rounds*2)],
                                                                               tk[r+(rounds*2)],
                                                                               (nibble*4)+3,
                                                                               (nibble*4)+2)   #x3->x2
                    command += "ASSERT({0}[{2}:{2}] = {1}[{3}:{3}]);\n".format(tk_after_pt[(r-1)+(rounds*2)],
                                                                               tk[r+(rounds*2)],
                                                                               (nibble*4)+2,
                                                                               (nibble*4)+1)   #x2->x1
                    command += "ASSERT({0}[{2}:{2}] = {1}[{3}:{3}]);\n".format(tk_after_pt[(r-1)+(rounds*2)],
                                                                               tk[r+(rounds*2)],
                                                                               (nibble*4)+1,
                                                                               (nibble*4)+0)   #x1->x0
                command += "ASSERT({}[63:32] = {}[63:32]);\n".format(tk_after_pt[(r-1)+(rounds*2)], tk[r+(rounds*2)])
        stp_file.write(command)
        return

    def setupSkinnyRound(self, stp_file, sc_in, atk, sr, mc, sc_out, w, blocksize, nrOfTK, tk1=None, tk2=None, tk3=None):
        """
        Model for differential behaviour of one round Skinny
        """
        command = ""
        #Add S-box transitions
        #for i in range(16):
        #    command += self.addSbox(sc_in, sr, 4*i)

        #AddRoundTweakey
        #add round tweakeys to first two rows of the state
        if nrOfTK == 1:
            tk = "{}[31:0]".format(tk1)
        elif nrOfTK == 2:
            tk = "BVXOR({}[31:0], {}[31:0])".format(tk1, tk2)
        elif nrOfTK == 3:
            tk = "BVXOR({}[31:0], BVXOR({}[31:0], {}[31:0]))".format(tk1, tk2, tk3)

        command += "ASSERT({}[31:0] = BVXOR({}[31:0], {}));\n".format(sr, atk, tk)
        command += "ASSERT({}[63:32] = {}[63:32]);\n".format(sr, atk)

        #ShiftRows
        command += "ASSERT({1}[15:0] = {0}[15:0]);\n".format(sr, mc)

        command += "ASSERT({1}[31:20] = {0}[27:16]);\n".format(sr, mc)
        command += "ASSERT({1}[19:16] = {0}[31:28]);\n".format(sr, mc)

        command += "ASSERT({1}[39:32] = {0}[47:40]);\n".format(sr, mc)
        command += "ASSERT({1}[47:40] = {0}[39:32]);\n".format(sr, mc)

        command += "ASSERT({1}[63:60] = {0}[51:48]);\n".format(sr, mc)
        command += "ASSERT({1}[59:48] = {0}[63:52]);\n".format(sr, mc)

        #MixColumns
        command += "ASSERT("
        command += "{0}[15:0] = {1}[31:16]".format(mc, sc_out);
        command += ");\n"

        command += "ASSERT("
        command += "BVXOR({0}[31:16], {0}[47:32]) = {1}[47:32]".format(mc, sc_out);
        command += ");\n"

        command += "ASSERT("
        command += "BVXOR({0}[47:32], {0}[15:0]) = {1}[63:48]".format(mc, sc_out);
        command += ");\n"

        command += "ASSERT("
        command += "BVXOR({0}[63:48], {1}[63:48]) = {1}[15:0]".format(mc, sc_out);
        command += ");\n"

        # TODO: correctly compute weight
        # For now just take the Hamming weight        
        for i in range(16):
            variables = ["{0}[{1}:{1}]".format(sc_in, 4*i + 3),
                         "{0}[{1}:{1}]".format(sc_in, 4*i + 2),
                         "{0}[{1}:{1}]".format(sc_in, 4*i + 1),
                         "{0}[{1}:{1}]".format(sc_in, 4*i + 0),
                         "{0}[{1}:{1}]".format(atk, 4*i + 3),
                         "{0}[{1}:{1}]".format(atk, 4*i + 2),
                         "{0}[{1}:{1}]".format(atk, 4*i + 1),
                         "{0}[{1}:{1}]".format(atk, 4*i + 0),
                         "{0}[{1}:{1}]".format(w, 4*i + 3),
                         "{0}[{1}:{1}]".format(w, 4*i + 2),
                         "{0}[{1}:{1}]".format(w, 4*i + 1),
                         "{0}[{1}:{1}]".format(w, 4*i + 0)]
            #command += stpcommands.add4bitSbox(self.skinny_sbox, variables)
            command += self.constraints_by_skinny_sbox(variables)            


        stp_file.write(command)
        return