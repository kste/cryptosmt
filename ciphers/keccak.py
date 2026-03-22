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

    @property
    def name(self):
        return "keccak"

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
        Declare variables for Keccak.
        """
        wordsize = parameters["wordsize"]
        rounds = parameters["rounds"]
        
        # Setup variables
        # 5x5 lanes of wordsize
        self.s = ["s{}{}{}".format(x, y, i) for i in range(rounds + 1)
                 for y in range(5) for x in range(5)]
        self.a = ["a{}{}{}".format(x, y, i) for i in range(rounds + 1)
                 for y in range(5) for x in range(5)]
        self.b = ["b{}{}{}".format(x, y, i) for i in range(rounds + 1)
                 for y in range(5) for x in range(5)]
        self.c = ["c{}{}".format(x, i) for i in range(rounds + 1) for x in range(5)]
        self.d = ["d{}{}".format(x, i) for i in range(rounds + 1) for x in range(5)]

        stpcommands.setupVariables(stp_file, self.s, wordsize)
        stpcommands.setupVariables(stp_file, self.a, wordsize)
        stpcommands.setupVariables(stp_file, self.b, wordsize)
        stpcommands.setupVariables(stp_file, self.c, wordsize)
        stpcommands.setupVariables(stp_file, self.d, wordsize)
        
        # Non-zero on state
        self.state_variables = self.s

    def apply_constraints(self, stp_file, parameters):
        """
        Override to handle fixed capacity before round loop.
        """
        wordsize = parameters["wordsize"]
        capacity = parameters.get("capacity", 160)
        rate = (wordsize * 25) - capacity
        if "rate" in parameters:
            rate = parameters["rate"]

        # Fix variables for capacity
        for i in range(rate // wordsize, (rate + capacity) // wordsize):
            stpcommands.assertVariableValue(stp_file, self.s[i], "0hex{}".format(
                "0" * (wordsize // 4)))
        
        # Call parent apply_constraints which handles the round loop
        super().apply_constraints(stp_file, parameters)

    def apply_round_constraints(self, stp_file, round_nr, parameters):
        """
        Keccak round constraints.
        """
        wordsize = parameters["wordsize"]
        self.setupKeccakRound(stp_file, round_nr, self.s, self.a, self.b, self.c, self.d, wordsize)

    def setupKeccakRound(self, stp_file, rnd, s, a, b, c, d, wordsize):
        """
        Model for one round of Keccak.
        """
        command = ""

        # Theta
        for x in range(5):
            # c[x] = s[x,0] xor s[x,1] xor s[x,2] xor s[x,3] xor s[x,4]
            command += "ASSERT({} = BVXOR({}, BVXOR({}, BVXOR({}, BVXOR({}, {})))));\n".format(
                c[5*rnd + x], s[25*rnd + 5*0 + x], s[25*rnd + 5*1 + x],
                s[25*rnd + 5*2 + x], s[25*rnd + 5*3 + x], s[25*rnd + 5*4 + x])

        for x in range(5):
            # d[x] = c[x-1] xor rot(c[x+1], 1)
            command += "ASSERT({} = BVXOR({}, {}));\n".format(
                d[5*rnd + x], c[5*rnd + (x - 1) % 5],
                rotl(c[5*rnd + (x + 1) % 5], 1, wordsize))

        for x in range(5):
            for y in range(5):
                # a[x,y] = s[x,y] xor d[x]
                command += "ASSERT({} = BVXOR({}, {}));\n".format(
                    a[25*rnd + 5*y + x], s[25*rnd + 5*y + x], d[5*rnd + x])

        # Rho and Phi
        for x in range(5):
            for y in range(5):
                # b[y, 2x+3y] = rot(a[x,y], RO[x,y])
                command += "ASSERT({} = {});\n".format(
                    b[25*rnd + 5*((2*x + 3*y) % 5) + y],
                    rotl(a[25*rnd + 5*y + x], self.RO[y][x], wordsize))

        # Chi
        for x in range(5):
            for y in range(5):
                # s[x,y] = b[x,y] xor (not b[x+1,y] and b[x+2,y])
                command += "ASSERT({} = BVXOR({}, (~{} & {})));\n".format(
                    s[25*(rnd+1) + 5*y + x], b[25*rnd + 5*y + x],
                    b[25*rnd + 5*y + (x + 1) % 5], b[25*rnd + 5*y + (x + 2) % 5])

        stp_file.write(command)
        return
