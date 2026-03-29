'''
Created on Oct 14, 2014

@author: stefan
@author: Laurent Tramoy
'''

from parser import stpcommands
from ciphers.cipher import AbstractCipher

from parser.stpcommands import getStringLeftRotate as rotl


class KeccakDiffCipher(AbstractCipher):
    """
    This class provides a model for the differential behaviour
    of the Keccak hash function by Guido Bertoni, Joan Daemen, 
    Michael Peeters and Gilles Van Assche.
    
    For more information on Keccak see http://keccak.noekeon.org/    
    """

    @property
    def name(self):
        return "keccakdiff"

    RO = [[0,  36,  3, 41, 18],
          [1,  44, 10, 45,  2],
          [62,  6, 43, 15, 61],
          [28, 55, 25, 21, 56],
          [27, 20, 39,  8, 14]]

    def getFormatString(self):
        """
        Returns the print format.
        """
        return ['s00', 's10', 's20', 's30', 's40',
                's01', 's11', 's21', 's31', 's41',
                's02', 's12', 's22', 's32', 's42',
                's03', 's13', 's23', 's33', 's43',
                's04', 's14', 's24', 's34', 's44', "w"]

    def write_header(self, stp_file, parameters):
        """
        Custom header for Keccak.
        """
        wordsize = parameters["wordsize"]
        rounds = parameters["rounds"]
        
        # Default rate and capacity
        capacity = 160
        rate = (wordsize * 25) - capacity

        if "rate" in parameters:
            rate = parameters["rate"]

        if "capacity" in parameters:
            capacity = parameters["capacity"]

        header = ("% Input File for STP\n% Keccak w={} rate={} "
                  "capacity={}\n\n\n".format(wordsize, rate, capacity,
                                              rounds))
        stp_file.write(header)

    def setup_variables(self, stp_file, parameters):
        """
        Declare variables in the STP file.
        """
        wordsize = parameters["wordsize"]
        rounds = parameters["rounds"]
        
        self.s = ["s{}{}{}".format(x, y, i) for i in range(rounds+1)
                 for y in range(5) for x in range(5)]

        self.b = ["b{}{}{}".format(x, y, i) for i in range(rounds)
                 for y in range(5) for x in range(5)]
        self.c = ["c{}{}".format(x, i) for i in range(rounds) for x in range(5)]
        self.d = ["d{}{}".format(x, i) for i in range(rounds) for x in range(5)]
        self.xin = ["xin{}{}{}".format(y, z, i) for i in range(rounds)
                   for y in range(5) for z in range (wordsize)]
        self.xout = ["xout{}{}{}".format(y, z, i) for i in range(rounds)
                    for y in range(5) for z in range (wordsize)]
        self.andOut = ["andOut{}{}{}".format(y, z, i) for i in range(rounds)
                      for y in range(5) for z in range (wordsize)]

        self.w = ["w{}".format(i) for i in range(rounds)]
        self.tmp = ["tmp{}{}{}".format(y, z, i) for i in range(rounds) 
                   for y in range(5) for z in range (wordsize)]
        
        stpcommands.setupVariables(stp_file, self.s, wordsize)
        stpcommands.setupVariables(stp_file, self.b, wordsize)
        stpcommands.setupVariables(stp_file, self.c, wordsize)
        stpcommands.setupVariables(stp_file, self.d, wordsize)
        stpcommands.setupVariables(stp_file, self.w, 16)
        stpcommands.setupVariables(stp_file, self.tmp, 5)
        
        weight = parameters["sweight"]
        stpcommands.setupWeightComputationSum(stp_file, weight, self.w, wordsize)
        
        stpcommands.setupVariables(stp_file, self.xin, 5)
        stpcommands.setupVariables(stp_file, self.xout, 5)
        stpcommands.setupVariables(stp_file, self.andOut, 5)

    def apply_constraints(self, stp_file, parameters):
        """
        Apply Keccak-specific constraints.
        """
        wordsize = parameters["wordsize"]
        rounds = parameters["rounds"]
        
        capacity = parameters.get("capacity", 160)
        rate = (wordsize * 25) - capacity
        if "rate" in parameters:
            rate = parameters["rate"]

        # No all zero characteristic
        stpcommands.assertNonZero(stp_file, self.s, wordsize)

        # Fix variables for capacity, only works if rate/capacity is
        # multiple of wordsize.
        for i in range(rate // wordsize, (rate + capacity) // wordsize):
           stpcommands.assertVariableValue(stp_file, self.s[i],
                                           "0hex{}".format("0"*(wordsize // 4)))

        # Standard round loop
        for i in range(rounds):
            self.apply_round_constraints(stp_file, i, parameters)

    def apply_round_constraints(self, stp_file, round_nr, parameters):
        """
        Model for one round of Keccak.
        """
        wordsize = parameters["wordsize"]
        rnd = round_nr
        s, b, c, d = self.s, self.b, self.c, self.d
        tmp, w = self.tmp, self.w
        xin, xout, andOut = self.xin, self.xout, self.andOut
        
        command = ""

        # Linear functions
        for i in range(5):
            command += "ASSERT({} = BVXOR({}, BVXOR({}, BVXOR({}, BVXOR({}, {})))));\n".format(
                c[i + 5*rnd], s[i + 5*0 + 25*rnd], s[i + 5*1 + 25*rnd],
                s[i + 5*2 + 25*rnd], s[i + 5*3 + 25*rnd], s[i + 5*4 + 25*rnd])

        # Compute intermediate values
        for i in range(5):
            command += "ASSERT({} = BVXOR({}, {}));\n".format(
                d[i + 5*rnd], c[(i - 1) % 5 + 5*rnd],
                rotl(c[(i + 1) % 5 + 5*rnd], 1, wordsize))

        # Rho and Pi
        for x in range(5):
            for y in range(5):
                new_b_index = y + 5*((2*x + 3*y) % 5) + 25*rnd
                tmp_xor = "BVXOR({}, {})".format(s[x + 5*y + 25*rnd], d[x + 5*rnd])
                command += "ASSERT({} = {});\n".format(
                    b[new_b_index], rotl(tmp_xor, self.RO[x][y], wordsize))

        # Chi
        rot_alpha = 2
        rot_beta = 1
        weight_sum = ""

        for y in range(5):
            for z in range(wordsize):
                # Construct S-box input
                command += "ASSERT({}={});\n".format(
                    xin[z + wordsize*y + 5*wordsize*rnd],
                    b[0 + 5*y + 25*rnd] + "[{0}:{0}]".format(z) + "@" +
                    b[1 + 5*y + 25*rnd] + "[{0}:{0}]".format(z) + "@" +
                    b[2 + 5*y + 25*rnd] + "[{0}:{0}]".format(z) + "@" +
                    b[3 + 5*y + 25*rnd] + "[{0}:{0}]".format(z) + "@" +
                    b[4 + 5*y + 25*rnd] + "[{0}:{0}]".format(z))

                # Construct S-box output
                command += "ASSERT({}={});\n".format(
                    xout[z + wordsize*y + 5*wordsize*rnd],
                    s[0 + 5*y + 25*(rnd+1)] + "[{0}:{0}]".format(z) + "@" +
                    s[1 + 5*y + 25*(rnd+1)] + "[{0}:{0}]".format(z) + "@" +
                    s[2 + 5*y + 25*(rnd+1)] + "[{0}:{0}]".format(z) + "@" +
                    s[3 + 5*y + 25*(rnd+1)] + "[{0}:{0}]".format(z) + "@" +
                    s[4 + 5*y + 25*(rnd+1)] + "[{0}:{0}]".format(z))

                xin_rotalpha = rotl(xin[z + wordsize*y + 5*wordsize*rnd], rot_alpha, 5)
                xin_rotbeta = rotl(xin[z + wordsize*y + 5*wordsize*rnd], rot_beta, 5)

                #Deal with dependent inputs
                varibits = "({0} | {1})".format(xin_rotalpha, xin_rotbeta)
                doublebits = self.getDoubleBits(xin[z + wordsize*y + 5*wordsize*rnd], rot_alpha, rot_beta)

                #Check for valid difference
                firstcheck = "({} & ~{})".format(andOut[z + wordsize*y + 5*wordsize*rnd], varibits)
                secondcheck = "(~BVXOR({}, {}) & {})".format(
                andOut[z + wordsize*y + 5*wordsize*rnd], rotl(andOut[z + wordsize*y + 5*wordsize*rnd], rot_alpha - rot_beta, 5), doublebits)
                thirdcheck = "(IF {0} = 0b{1} THEN BVMOD(5, {0}, 0b00010) ELSE 0b{2}ENDIF)".format(
                xin[z + wordsize*y + 5*wordsize*rnd], "11111", "00000")
                command += "ASSERT(({} | {} | {}) = 0b{});\n".format(firstcheck,
                secondcheck, thirdcheck, "00000")

                #Assert XORs
                command += "ASSERT({} = BVXOR({},{}));\n".format(
                    xout[z + wordsize*y + 5*wordsize*rnd], 
                    xin[z + wordsize*y + 5*wordsize*rnd], 
                    andOut[z + wordsize*y + 5*wordsize*rnd])

                #Weight computation
                if rnd != 3:
                    command += ("ASSERT({0} = (IF {1} = 0b{4} THEN BVSUB({5},0b{4},0b{6}1)"
                            "ELSE BVXOR({2}, {3}) ENDIF));\n".format(
                                tmp[z + wordsize*y + 5*wordsize*rnd], 
                                xin[z + wordsize*y + 5*wordsize*rnd], 
                                varibits, doublebits, "1"*5,
                                5, "0"*4))
                else:
                    command += ("ASSERT({0} = {1});\n".format(
                                tmp[z + wordsize*y + 5*wordsize*rnd], 
                                "0b00000"))

                weight_sum += ("0b{0}@(BVPLUS({1}, {2}[0:0], {2}[1:1], "
                               "{2}[2:2],{2}[3:3], {2}[4:4])),".format(
                                    "0"*11, 5, "0b0000@" + 
                                    tmp[z + wordsize*y + 5*wordsize*rnd]))

        command += "ASSERT({}=BVPLUS({},{}));\n".format(w[rnd], 16, weight_sum[:-1])

        stp_file.write(command)
        return

    def getDoubleBits(self, xin, rot_alpha, rot_beta):
        command = "({0} & ~{1} & {2})".format(
            rotl(xin, rot_beta, 5), rotl(xin, rot_alpha, 5),
            rotl(xin, 2*rot_alpha - rot_beta, 5))
        return command
