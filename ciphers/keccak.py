'''
Created on Oct 14, 2014

@author: stefan
'''

from parser import stpcommands
from ciphers.cipher import AbstractCipher

from parser.stpcommands import getStringLeftRotate as rotl


class KeccakCipher(AbstractCipher):
    """
    This class provides a model for the Keccak hash function by
    Guido Bertoni, Joan Daemen, Michael Peeters and Gilles Van Assche.
    
    For more information on Keccak see http://keccak.noekeon.org/
    """

    name = "keccak"

    RO = [[0,  36,  3, 41, 18],
          [1,  44, 10, 45,  2],
          [62,  6, 43, 15, 61],
          [28, 55, 25, 21, 56],
          [27, 20, 39,  8, 14]]

    RC = ["0hex0001", "0hex8082", "0hex808A", "0hex8000", "0hex808B",
          "0hex0001", "0hex8081", "0hex8009"]

    def getFormatString(self):
        return ['s00', 's10', 's20', 's30', 's40',
                's01', 's11', 's21', 's31', 's41',
                's02', 's12', 's22', 's32', 's42',
                's03', 's13', 's23', 's33', 's43',
                's04', 's14', 's24', 's34', 's44']

    def createSTP(self, stp_filename, parameters):
        """
        Creates an STP file to find a preimage for Keccak.
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

        assert (rate + capacity) == wordsize * 25            

        with open(stp_filename, 'w') as stp_file:
            stp_file.write("% Input File for STP\n% Keccak w={} rate={} "
                           "capacity={}\n\n\n".format(wordsize, rate, capacity,
                                                      rounds))

            # Setup variables
            # 5x5 lanes of wordsize
            s = ["s{}{}{}".format(x, y, i) for i in range(rounds + 1)
                 for y in range(5) for x in range(5)]
            a = ["a{}{}{}".format(x, y, i) for i in range(rounds + 1)
                 for y in range(5) for x in range(5)]
            b = ["b{}{}{}".format(x, y, i) for i in range(rounds + 1)
                 for y in range(5) for x in range(5)]
            c = ["c{}{}".format(x, i) for i in range(rounds + 1) for x in range(5)]
            d = ["d{}{}".format(x, i) for i in range(rounds + 1) for x in range(5)]

            stpcommands.setupVariables(stp_file, s, wordsize)
            stpcommands.setupVariables(stp_file, a, wordsize)
            stpcommands.setupVariables(stp_file, b, wordsize)
            stpcommands.setupVariables(stp_file, c, wordsize)
            stpcommands.setupVariables(stp_file, d, wordsize)

            # Fix variables for capacity, only works if rate/capacity 
            # is multiple of wordsize
            for i in range(rate // wordsize, (rate + capacity) // wordsize):
                stpcommands.assertVariableValue(stp_file, s[i], "0hex{}".format(
                    "0" * (wordsize // 4)))

            for rnd in range(rounds):
                self.setupKeccakRound(stp_file, rnd, s, a, b, c, d, wordsize)

            for key, value in parameters["fixedVariables"].items():
                stpcommands.assertVariableValue(stp_file, key, value)

            stpcommands.setupQuery(stp_file)

        return

    def setupKeccakRound(self, stp_file, rnd, s, a, b, c, d, wordsize):
        """
        Model for one round of Keccak.
        """
        command = ""

        #Compute Parity for each column
        for i in range(5):
            command += "ASSERT({} = BVXOR({}, BVXOR({}, BVXOR({}, BVXOR({}, {})))));\n".format(
                c[i + 5*rnd], s[i + 5*0 + 25*rnd], s[i + 5*1 + 25*rnd],
                s[i + 5*2 + 25*rnd], s[i + 5*3 + 25*rnd], s[i + 5*4 + 25*rnd])

        #Compute intermediate values
        for i in range(5):
            command += "ASSERT({} = BVXOR({}, {}));\n".format(
                d[i + 5*rnd], c[(i - 1) % 5 + 5*rnd],
                rotl(c[(i + 1) % 5 + 5*rnd], 1, wordsize))

        #Rho and Pi
        for x in range(5):
            for y in range(5):
                #x + 5*y + 25*rnd -> y + 5*((2*x + 3*y) % 5) + 25*rnd
                new_b_index = y + 5*((2*x + 3*y) % 5) + 25*rnd
                tmp_xor = "BVXOR({}, {})".format(s[x + 5*y + 25*rnd], d[x + 5*rnd])
                command += "ASSERT({} = {});\n".format(
                    b[new_b_index], rotl(tmp_xor, self.RO[x][y], wordsize))

        #Chi
        for x in range(5):
            for y in range(5):
                chiTmp = "BVXOR({}, ~{} & {})".format(b[(x + 0) % 5 + 5*y + 25*rnd],
                                                      b[(x + 1) % 5 + 5*y + 25*rnd],
                                                      b[(x + 2) % 5 + 5*y + 25*rnd])
                command += "ASSERT({} = {});\n".format(a[x + 5*y + 25*rnd], chiTmp)

        #Add rnd constant
        for x in range(5):
            for y in range(5):
                if x == 0 and y == 0:
                    command += "ASSERT({} = BVXOR({}, {}));\n".format(
                        s[25*(rnd + 1)], a[25*rnd], self.RC[rnd])
                else:
                    command += "ASSERT({} = {});\n".format(
                        s[x + 5*y + 25*(rnd + 1)], a[x + 5*y + 25*rnd])

        stp_file.write(command)
        return
