'''
Created on Dec 18, 2015

@author: stefan
'''

from parser import stpcommands
from ciphers.cipher import AbstractCipher
from ciphers import components

from parser.stpcommands import getStringLeftRotate as rotl
from parser.stpcommands import getStringRightRotate as rotr


class AsconCipher(AbstractCipher):
    """
    This class provides a differential model of the Ascon authenticated
    encryption scheme by Christoph Dobrauning, Maria Eichlseder, Florian
    Mendel and Martin Schläffer.

    For more information on Ascon see http://ascon.iaik.tugraz.at/
    """

    @property
    def name(self):
        return "ascon"

    def getFormatString(self):
        """
        Returns the print format.
        """
        return ['s0', 's1', 's2', 's3', 's4',
                'b0', 'b1', 'b2', 'b3', 'b4', "w"]

    def write_header(self, stp_file, parameters):
        """
        Custom header for Ascon.
        """
        wordsize = parameters["wordsize"]
        rounds = parameters["rounds"]
        capacity = parameters.get("capacity", 0)
        rate = (wordsize * 5) - capacity
        if "rate" in parameters:
            rate = parameters["rate"]

        header = ("% Input File for STP\n% Ascon w={} rate={} "
                  "capacity={} round={}\n\n\n".format(wordsize, rate, capacity,
                                                      rounds))
        stp_file.write(header)

    def setup_variables(self, stp_file, parameters):
        """
        Declare variables for Ascon.
        """
        wordsize = parameters["wordsize"]
        rounds = parameters["rounds"]
        sboxsize = 5

        # 5 x wordsize state
        self.s = ["s{}{}".format(x, i) for i in range(rounds+1)
                 for x in range(sboxsize)]
        # Output after S-box Linear part 1
        self.a = ["a{}{}".format(x, i) for i in range(rounds+1)
                 for x in range(sboxsize)]
        # Output after S-box Non-Linear part
        self.b = ["b{}{}".format(x, i) for i in range(rounds+1)
                 for x in range(sboxsize)]
        # Output after S-box Linear part 2
        self.c = ["c{}{}".format(x, i) for i in range(rounds+1)
                 for x in range(sboxsize)]

        # Inputs/Output to the S-box
        self.xin = ["inx{}{}{}".format(y, z, i) for i in range(rounds)
                   for y in range(sboxsize) for z in range (wordsize)]
        self.xout = ["outx{}{}{}".format(y, z, i) for i in range(rounds)
                    for y in range(sboxsize) for z in range (wordsize)]
        self.andout = ["andout{}{}{}".format(y, z, i) for i in range(rounds)
                      for y in range(sboxsize) for z in range (wordsize)]

        # w = weight
        self.w = ["w{}".format(i) for i in range(rounds)]
        self.tmp = ["tmp{}{}{}".format(y, z, i) for i in range(rounds)
                   for y in range(sboxsize) for z in range (wordsize)]

        stpcommands.setupVariables(stp_file, self.s, wordsize)
        stpcommands.setupVariables(stp_file, self.a, wordsize)
        stpcommands.setupVariables(stp_file, self.b, wordsize)
        stpcommands.setupVariables(stp_file, self.c, wordsize)
        stpcommands.setupVariables(stp_file, self.w, 16)
        stpcommands.setupVariables(stp_file, self.tmp, sboxsize)
        stpcommands.setupVariables(stp_file, self.xin, sboxsize)
        stpcommands.setupVariables(stp_file, self.xout, sboxsize)
        stpcommands.setupVariables(stp_file, self.andout, sboxsize)
        
        # Register state for non-zero constraint
        self.state_variables = self.s

    def apply_constraints(self, stp_file, parameters):
        """
        Apply Ascon specific constraints.
        """
        wordsize = parameters["wordsize"]
        rounds = parameters["rounds"]
        weight = parameters["sweight"]
        
        capacity = parameters.get("capacity", 0)
        rate = (wordsize * 5) - capacity
        if "rate" in parameters:
            rate = parameters["rate"]

        # Weight computation (Ascon uses setupWeightComputationSum)
        stpcommands.setupWeightComputationSum(stp_file, weight, self.w, wordsize)

        # Fix variables for capacity
        for i in range(rate // wordsize, (rate + capacity) // wordsize):
            stpcommands.assertVariableValue(stp_file, self.s[i],
                                            "0hex{}".format("0"*(wordsize // 4)))

        # Standard round loop from AbstractCipher template
        super().apply_constraints(stp_file, parameters)

    def apply_round_constraints(self, stp_file, round_nr, parameters):
        """
        Ascon round logic.
        """
        wordsize = parameters["wordsize"]
        self.setupAsconRound(stp_file, round_nr, self.s, self.a, self.b, self.c, wordsize, self.tmp,
                             self.w, self.xin, self.xout, self.andout)

    def setupAsconRound(self, stp_file, rnd, s, a, b, c, wordsize, tmp,
                        w, xin, xout, andout):
        """
        Model for one round of Ascon.
        """
        command = ""
        weight_sum = ""

        # Linear part in S-box
        command += "ASSERT({} = BVXOR({}, {}));\n".format(a[0 + 5*rnd],
                                                          s[0 + 5*rnd],
                                                          s[4 + 5*rnd])
        command += "ASSERT({} = {});\n".format(a[1 + 5*rnd], s[1 + 5*rnd])
        command += "ASSERT({} = BVXOR({}, {}));\n".format(a[2 + 5*rnd],
                                                          s[2 + 5*rnd],
                                                          s[1 + 5*rnd])
        command += "ASSERT({} = {});\n".format(a[3 + 5*rnd], s[3 + 5*rnd])
        command += "ASSERT({} = BVXOR({}, {}));\n".format(a[4 + 5*rnd],
                                                          s[4 + 5*rnd],
                                                          s[3 + 5*rnd])


        # Model for the S-box

        for z in range(wordsize):
            # Construct S-box input
            command += "ASSERT({}={});\n".format(
                xin[z + 5*wordsize*rnd],
                a[0 + 5*rnd] + "[{0}:{0}]".format(z) + "@" +
                a[1 + 5*rnd] + "[{0}:{0}]".format(z) + "@" +
                a[2 + 5*rnd] + "[{0}:{0}]".format(z) + "@" +
                a[3 + 5*rnd] + "[{0}:{0}]".format(z) + "@" +
                a[4 + 5*rnd] + "[{0}:{0}]".format(z))

            # Construct S-box output
            command += "ASSERT({}={});\n".format(
                xout[z + 5*wordsize*rnd],
                b[0 + 5*rnd] + "[{0}:{0}]".format(z) + "@" +
                b[1 + 5*rnd] + "[{0}:{0}]".format(z) + "@" +
                b[2 + 5*rnd] + "[{0}:{0}]".format(z) + "@" +
                b[3 + 5*rnd] + "[{0}:{0}]".format(z) + "@" +
                b[4 + 5*rnd] + "[{0}:{0}]".format(z))

            xin_rotalpha = rotl(xin[z + 5*wordsize*rnd], 2, 5)
            xin_rotbeta = rotl(xin[z + 5*wordsize*rnd], 1, 5)

            #Deal with dependent inputs
            varibits = "({0} | {1})".format(xin_rotalpha, xin_rotbeta)
            doublebits = self.getDoubleBits(xin[z + 5*wordsize*rnd])

            #Check for valid difference
            firstcheck = "({} & ~{})".format(andout[z + 5*wordsize*rnd], varibits)
            secondcheck = "(~BVXOR({}, {}) & {})".format(
            andout[z + 5*wordsize*rnd], rotl(andout[z + 5*wordsize*rnd], 2 - 1, 5), doublebits)
            thirdcheck = "(IF {0} = 0b{1} THEN BVMOD(5, {0}, 0b00010) ELSE 0b{2}ENDIF)".format(
                xin[z + 5*wordsize*rnd], "11111", "00000")
            command += "ASSERT(({} | {} | {}) = 0b{});\n".format(firstcheck,
            secondcheck, thirdcheck, "00000")

            #Assert XORs
            command += "ASSERT({} = BVXOR({},{}));\n".format(
                xout[z + 5*wordsize*rnd], 
                xin[z + 5*wordsize*rnd], 
                andout[z + 5*wordsize*rnd])

            #Weight computation
            command += ("ASSERT({0} = (IF {1} = 0b{4} THEN BVSUB({5},0b{4},0b{6}1)"
                        "ELSE BVXOR({2}, {3}) ENDIF));\n".format(
                            self.tmp[z + 5*wordsize*rnd], 
                            xin[z + 5*wordsize*rnd], 
                            varibits, doublebits, "1"*5,
                            5, "0"*4))

            weight_sum += ("0b{0}@(BVPLUS({1}, {2}[0:0], {2}[1:1], "
                "{2}[2:2],{2}[3:3], {2}[4:4])),".format("0"*11, 5, "0b0000@" +
                                                        self.tmp[z + 5*wordsize*rnd]))

        command += "ASSERT({}=BVPLUS({},{}));\n".format(w[rnd], 16, 
                                                        weight_sum[:-1])

        # Linear after S-box
        command += "ASSERT({} = BVXOR({}, {}));\n".format(c[0 + 5*rnd],
                                                          b[0 + 5*rnd],
                                                          b[4 + 5*rnd])
        command += "ASSERT({} = BVXOR({}, {}));\n".format(c[1 + 5*rnd],
                                                          b[0 + 5*rnd],
                                                          b[1 + 5*rnd])
        command += "ASSERT({} = {});\n".format(c[2 + 5*rnd], b[2 + 5*rnd])
        command += "ASSERT({} = BVXOR({}, {}));\n".format(c[3 + 5*rnd],
                                                          b[2 + 5*rnd],
                                                          b[3 + 5*rnd])
        command += "ASSERT({} = {});\n".format(c[4 + 5*rnd], b[4 + 5*rnd])


        # Linear functions
        rot_constants = [[19, 28], [61, 39], [1, 6], [10, 17], [7, 41]]
        for row in range(5):
            command += "ASSERT({} = BVXOR({}, BVXOR({}, {})));\n".format(
                s[row + 5 * (rnd + 1)],
                c[row + 5*rnd],
                rotr(c[row + 5*rnd], rot_constants[row][0], wordsize),
                rotr(c[row + 5*rnd], rot_constants[row][1], wordsize),
            )

        stp_file.write(command)
        return

    def getDoubleBits(self, xin):
        command = "({0} & ~{1} & {2})".format(
            rotl(xin, 1, 5), rotl(xin, 2, 5),
            rotl(xin, 2*2 - 1, 5))
        return command
