'''
Created on Jan 6, 2017

@author: stefan
'''

from parser import stpcommands
from ciphers.cipher import AbstractCipher
from ciphers import components


class GimliCipher(AbstractCipher):
    """
    Represents the differential behaviour of the Gimli permutation.
    """

    @property
    def name(self):
        return "gimli"

    # Standard Constants
    a = 2; b = 1; c = 3
    d = 0; e = 9; f = 24

    def getFormatString(self):
        """
        Returns the print format.
        """
        return ['x0', 'y0', 'z0', 'x1', 'y1', 'z1', 'x2', 'y2', 'z2', 'x3', 'y3', 'z3', 'rw']

    def validate_parameters(self, parameters):
        if "rotationconstants" in parameters and parameters["rotationconstants"]:
            self.d, self.e, self.f = parameters["rotationconstants"][:3]

    def setup_variables(self, stp_file, parameters):
        """
        Declare variables for Gimli.
        """
        wordsize = parameters["wordsize"]
        rounds = parameters["rounds"]
        
        self.x = []; self.y = []; self.z = []
        for i in range(4):
            self.x.append(self.declare_variable_vector(stp_file, f"x{i}", rounds, wordsize, is_state=True))
            self.y.append(self.declare_variable_vector(stp_file, f"y{i}", rounds, wordsize, is_state=True))
            self.z.append(self.declare_variable_vector(stp_file, f"z{i}", rounds, wordsize, is_state=True))
        
        # We'll use self.w as the main weight variable for each round
        # In Gimli, weight is bitwise OR of individual SP-box weights
        self.w = self.declare_variable_vector_per_round(stp_file, "rw", rounds, wordsize, is_weight=True)
        # Individual weights per SP-box (internal)
        self.wp = []
        for i in range(4):
            self.wp.append(self.declare_variable_vector_per_round(stp_file, f"rwp{i}", rounds, wordsize))

    def apply_round_constraints(self, stp_file, round_nr, parameters):
        """
        Apply Gimli round logic.
        """
        wordsize = parameters["wordsize"]
        
        # Intermediate output of SP-boxes before swaps
        import random
        rnd = f"{random.randrange(16**8):08x}"
        xt = [f"gimli_xt{i}_{round_nr}_{rnd}" for i in range(4)]
        yt = [f"gimli_yt{i}_{round_nr}_{rnd}" for i in range(4)]
        zt = [f"gimli_zt{i}_{round_nr}_{rnd}" for i in range(4)]
        stpcommands.setupVariables(stp_file, xt + yt + zt, wordsize)

        # 4 SP-boxes
        for i in range(4):
            v_in = [self.x[i][round_nr], self.y[i][round_nr], self.z[i][round_nr]]
            v_out = [xt[i], yt[i], zt[i]]
            components.add_gimli_round(stp_file, v_in, v_out, self.wp[i][round_nr], wordsize, 
                                       self.a, self.b, self.c, self.d, self.e, self.f)

        # Combine individual SP-box weights into round weight rw
        # Bitwise OR is correct for Gimli model
        stp_file.write(f"ASSERT({self.w[round_nr]} = (({self.wp[0][round_nr]} | {self.wp[1][round_nr]}) | ({self.wp[2][round_nr]} | {self.wp[3][round_nr]})));\n")

        # Linear Layer (Swaps)
        r = (round_nr) & 3
        if r == 0: # Small Swap
            components.add_assignment(stp_file, self.x[0][round_nr+1], xt[1])
            components.add_assignment(stp_file, self.y[0][round_nr+1], yt[0])
            components.add_assignment(stp_file, self.z[0][round_nr+1], zt[0])
            components.add_assignment(stp_file, self.x[1][round_nr+1], xt[0])
            components.add_assignment(stp_file, self.y[1][round_nr+1], yt[1])
            components.add_assignment(stp_file, self.z[1][round_nr+1], zt[1])
            components.add_assignment(stp_file, self.x[2][round_nr+1], xt[3])
            components.add_assignment(stp_file, self.y[2][round_nr+1], yt[2])
            components.add_assignment(stp_file, self.z[2][round_nr+1], zt[2])
            components.add_assignment(stp_file, self.x[3][round_nr+1], xt[2])
            components.add_assignment(stp_file, self.y[3][round_nr+1], yt[3])
            components.add_assignment(stp_file, self.z[3][round_nr+1], zt[3])
        elif r == 2: # Big Swap
            components.add_assignment(stp_file, self.x[0][round_nr+1], xt[2])
            components.add_assignment(stp_file, self.y[0][round_nr+1], yt[0])
            components.add_assignment(stp_file, self.z[0][round_nr+1], zt[0])
            components.add_assignment(stp_file, self.x[1][round_nr+1], xt[3])
            components.add_assignment(stp_file, self.y[1][round_nr+1], yt[1])
            components.add_assignment(stp_file, self.z[1][round_nr+1], zt[1])
            components.add_assignment(stp_file, self.x[2][round_nr+1], xt[0])
            components.add_assignment(stp_file, self.y[2][round_nr+1], yt[2])
            components.add_assignment(stp_file, self.z[2][round_nr+1], zt[2])
            components.add_assignment(stp_file, self.x[3][round_nr+1], xt[1])
            components.add_assignment(stp_file, self.y[3][round_nr+1], yt[3])
            components.add_assignment(stp_file, self.z[3][round_nr+1], zt[3])
        else: # No Swap
            for i in range(4):
                components.add_assignment(stp_file, self.x[i][round_nr+1], xt[i])
                components.add_assignment(stp_file, self.y[i][round_nr+1], yt[i])
                components.add_assignment(stp_file, self.z[i][round_nr+1], zt[i])
