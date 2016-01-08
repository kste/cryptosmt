'''
Created on Oct 14, 2014

@author: stefan
@author: Laurent Tramoy
'''

from parser import stpcommands
from ciphers.cipher import AbstractCipher

from parser.stpcommands import getStringLeftRotate as rotl


class KetjeCipher(AbstractCipher):
    """
    This class provides a model for the differential behaviour of the
    Ketje authenticated encryption scheme by Guido Bertoni, Joan Daemen, 
    Michael Peeters, Gilles Van Assche and Ronny Van Keer.
    
    For more information on Ketje see http://competitions.cr.yp.to/round1/ketjev11.pdf
    """

    name = "ketje"

    RO = [[0,  36,  3, 41, 18],
          [1,  44, 10, 45,  2],
          [62,  6, 43, 15, 61],
          [28, 55, 25, 21, 56],
          [27, 20, 39,  8, 14]]

    def getFormatString(self):
        """
        Returns the print format.
        """
        return  ['s00', 's10', 's20', 's30', 's40',
                 's01', 's11', 's21', 's31', 's41',
                 's02', 's12', 's22', 's32', 's42',
                 's03', 's13', 's23', 's33', 's43',
                 's04', 's14', 's24', 's34', 's44',
                 'm0', 'm1', "w"]

    def createSTP(self, stp_filename, parameters):
        """
        Creates an STP file for Ketje.
        """
        wordsize = parameters["wordsize"]
        rounds = parameters["rounds"]
        weight = parameters["sweight"]

        with open(stp_filename, 'w') as stp_file:
            stp_file.write("% Input File for STP\n% Ketje w={} rounds={}"
                           "\n\n\n".format(wordsize, rounds))

            # Setup variables
            # 5x5 lanes of wordsize
            s = ["s{}{}{}".format(x, y, i) for i in range(rounds + 1)
                 for y in range(5) for x in range(5)]
            a = ["a{}{}{}".format(x, y, i) for i in range(rounds)
                 for y in range(5) for x in range(5)]
            b = ["b{}{}{}".format(x, y, i) for i in range(rounds)
                 for y in range(5) for x in range(5)]
            c = ["c{}{}".format(x, i) for i in range(rounds + 1) for x in range(5)]
            d = ["d{}{}".format(x, i) for i in range(rounds + 1) for x in range(5)]
            m = ["m{}{}".format(x, i) for i in range(rounds +1) for x in range(2)]
            xin = ["xin{}{}{}".format(y, z, i) for i in range(rounds)
                   for y in range(5) for z in range (wordsize)]
            xout = ["xout{}{}{}".format(y, z, i) for i in range(rounds)
                    for y in range(5) for z in range (wordsize)]
            andOut = ["andOut{}{}{}".format(y, z, i) for i in range(rounds)
                      for y in range(5) for z in range (wordsize)]

	        # w = weight
            w = ["w{}".format(i) for i in range(rounds)]
            tmp = ["tmp{}{}{}".format(y, z, i) for i in range(rounds) 
                   for y in range(5) for z in range (wordsize)]
            stpcommands.setupVariables(stp_file, s, wordsize)
            stpcommands.setupVariables(stp_file, a, wordsize)
            stpcommands.setupVariables(stp_file, b, wordsize)
            stpcommands.setupVariables(stp_file, c, wordsize)
            stpcommands.setupVariables(stp_file, d, wordsize)
            stpcommands.setupVariables(stp_file, w, 16)
            stpcommands.setupVariables(stp_file, tmp, 5)
            stpcommands.setupWeightComputationSum(stp_file, weight, w, wordsize)
            stpcommands.setupVariables(stp_file, xin, 5)
            stpcommands.setupVariables(stp_file, xout, 5)
            stpcommands.setupVariables(stp_file, andOut, 5)
            stpcommands.setupVariables(stp_file, m, wordsize)

            # No all zero characteristic
            stpcommands.assertNonZero(stp_file, a, wordsize)

            for rnd in range(rounds):
                self.setupKeccakRound(stp_file, rnd, s, a, b, c, d, wordsize, 
                                      tmp, w, m, xin, xout, andOut)

            for key, value in parameters["fixedVariables"].items():
                stpcommands.assertVariableValue(stp_file, key, value)

            stpcommands.setupQuery(stp_file)

        return

    def setupKeccakRound(self, stp_file, rnd, s, a, b, c, d, wordsize, tmp,
                         w, m, xin, xout, andOut):
        """
        Model for one round of Keccak.
        """
        command = ""

        #xor the state with the message for the first two words
        for x in range(5):
            for y in range(5):
                if(x == 0 and y == 0) or (x == 1 and y == 0):
                    command += "ASSERT({}=BVXOR({},{}));\n".format(
                    a[x + 5*y + 25*rnd], s[x + 5*y + 25*rnd], m[x + 2*rnd])
                else:
                    command += "ASSERT({}={});\n".format(
                    a[x + 5*y + 25*rnd], s[x + 5*y + 25*rnd])        

        # Linear functions
        for i in range(5):
            command += "ASSERT({} = BVXOR({}, BVXOR({}, BVXOR({}, BVXOR({}, {})))));\n".format(
                c[i + 5*rnd], a[i + 5*0 + 25*rnd], a[i + 5*1 + 25*rnd],
                a[i + 5*2 + 25*rnd], a[i + 5*3 + 25*rnd], a[i + 5*4 + 25*rnd])

        # Compute intermediate values
        for i in range(5):
            command += "ASSERT({} = BVXOR({}, {}));\n".format(
                d[i + 5*rnd], c[(i - 1) % 5 + 5*rnd],
                rotl(c[(i + 1) % 5 + 5*rnd], 1, wordsize))

        # Rho and Pi
        for x in range(5):
            for y in range(5):
                new_b_index = y + 5*((2*x + 3*y) % 5) + 25*rnd
                tmp_xor = "BVXOR({}, {})".format(a[x + 5*y + 25*rnd], d[x + 5*rnd])
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
                command += ("ASSERT({0} = (IF {1} = 0b{4} THEN BVSUB({5},0b{4},0b{6}1)"
                            "ELSE BVXOR({2}, {3}) ENDIF));\n".format(
                                tmp[z + wordsize*y + 5*wordsize*rnd], 
                                xin[z + wordsize*y + 5*wordsize*rnd], 
                                varibits, doublebits, "1"*5,
                                5, "0"*4))

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
