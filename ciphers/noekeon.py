'''
Created on Apr 3, 2017

@author: ralph
'''

from parser import stpcommands
from ciphers.cipher import AbstractCipher
from ciphers import components

class NoekeonCipher(AbstractCipher):
    """
    Represents the differential behaviour of NOEKEON and can be used
    to find differential characteristics for the given parameters.
    """

    @property
    def name(self):
        return "noekeon"

    def getFormatString(self):
        """
        Returns the print format.
        """
        return ['A0', 'A1', 'A2', 'A3', 'w']

    def validate_parameters(self, parameters):
        """
        Noekeon supports 32-bit wordsize (128-bit block).
        """
        if parameters["wordsize"] != 32:
            parameters["wordsize"] = 32

    def setup_variables(self, stp_file, parameters):
        """
        Declare variables for NOEKEON.
        """
        wordsize = parameters["wordsize"]
        rounds = parameters["rounds"]
        
        self.a0 = self.declare_variable_vector(stp_file, "A0", rounds, wordsize, is_state=True)
        self.a1 = self.declare_variable_vector(stp_file, "A1", rounds, wordsize, is_state=True)
        self.a2 = self.declare_variable_vector(stp_file, "A2", rounds, wordsize, is_state=True)
        self.a3 = self.declare_variable_vector(stp_file, "A3", rounds, wordsize, is_state=True)
        
        self.t0 = self.declare_variable_vector_per_round(stp_file, "T0", rounds, wordsize)
        self.t1 = self.declare_variable_vector_per_round(stp_file, "T1", rounds, wordsize)
        self.t2 = self.declare_variable_vector_per_round(stp_file, "T2", rounds, wordsize)
        self.t3 = self.declare_variable_vector_per_round(stp_file, "T3", rounds, wordsize)
        
        self.g0 = self.declare_variable_vector_per_round(stp_file, "G0", rounds, wordsize)
        self.g1 = self.declare_variable_vector_per_round(stp_file, "G1", rounds, wordsize)
        self.g2 = self.declare_variable_vector_per_round(stp_file, "G2", rounds, wordsize)
        self.g3 = self.declare_variable_vector_per_round(stp_file, "G3", rounds, wordsize)
        
        # Intermediate variables for Pi layers
        self.p10 = self.declare_variable_vector_per_round(stp_file, "PI10", rounds, wordsize)
        self.p11 = self.declare_variable_vector_per_round(stp_file, "PI11", rounds, wordsize)
        self.p12 = self.declare_variable_vector_per_round(stp_file, "PI12", rounds, wordsize)
        self.p13 = self.declare_variable_vector_per_round(stp_file, "PI13", rounds, wordsize)
        
        # w = weight (4 bits per S-box, 32 S-boxes)
        self.w = self.declare_variable_vector_per_round(stp_file, "w", rounds, wordsize*4, is_weight=True)

    def apply_round_constraints(self, stp_file, round_nr, parameters):
        """
        Apply NOEKEON round logic.
        """
        wordsize = parameters["wordsize"]
        from parser.stpcommands import getStringRightRotate as rotr
        from parser.stpcommands import getStringLeftRotate as rotl
        
        # Theta
        v_in = [self.a0[round_nr], self.a1[round_nr], self.a2[round_nr], self.a3[round_nr]]
        v_theta = [self.t0[round_nr], self.t1[round_nr], self.t2[round_nr], self.t3[round_nr]]
        components.add_noekeon_theta(stp_file, v_in, v_theta, wordsize)
        
        # Pi1
        components.add_assignment(stp_file, self.p10[round_nr], v_theta[0])
        components.add_assignment(stp_file, self.p11[round_nr], rotl(v_theta[1], 1, wordsize))
        components.add_assignment(stp_file, self.p12[round_nr], rotl(v_theta[2], 5, wordsize))
        components.add_assignment(stp_file, self.p13[round_nr], rotl(v_theta[3], 2, wordsize))
        
        # Gamma (S-box layer)
        noekeon_sbox = [7, 0xA, 2, 0xC, 4, 8, 0xF, 0, 5, 9, 1, 0xE, 3, 0xD, 0xB, 6]
        v_pi1 = [self.p10[round_nr], self.p11[round_nr], self.p12[round_nr], self.p13[round_nr]]
        v_gamma = [self.g0[round_nr], self.g1[round_nr], self.g2[round_nr], self.g3[round_nr]]
        
        # Bit-sliced S-box application
        for i in range(wordsize):
            inputs = [f"{v_pi1[3]}[{i}:{i}]", f"{v_pi1[2]}[{i}:{i}]", f"{v_pi1[1]}[{i}:{i}]", f"{v_pi1[0]}[{i}:{i}]"]
            outputs = [f"{v_gamma[3]}[{i}:{i}]", f"{v_gamma[2]}[{i}:{i}]", f"{v_gamma[1]}[{i}:{i}]", f"{v_gamma[0]}[{i}:{i}]"]
            weights = [f"{self.w[round_nr]}[{4*i+3}:{4*i+3}]", f"{self.w[round_nr]}[{4*i+2}:{4*i+2}]",
                       f"{self.w[round_nr]}[{4*i+1}:{4*i+1}]", f"{self.w[round_nr]}[{4*i+0}:{4*i+0}]"]
            components.add_4bit_sbox(stp_file, noekeon_sbox, inputs, outputs, weights)
            
        # Pi2
        components.add_assignment(stp_file, self.a0[round_nr+1], v_gamma[0])
        components.add_assignment(stp_file, self.a1[round_nr+1], rotr(v_gamma[1], 1, wordsize))
        components.add_assignment(stp_file, self.a2[round_nr+1], rotr(v_gamma[2], 5, wordsize))
        components.add_assignment(stp_file, self.a3[round_nr+1], rotr(v_gamma[3], 2, wordsize))

    def apply_iterative_constraints(self, stp_file, parameters):
        """
        Iterative constraint for NOEKEON.
        """
        rounds = parameters["rounds"]
        stpcommands.assertVariableValue(stp_file, self.a0[0], self.a0[rounds])
        stpcommands.assertVariableValue(stp_file, self.a1[0], self.a1[rounds])
        stpcommands.assertVariableValue(stp_file, self.a2[0], self.a2[rounds])
        stpcommands.assertVariableValue(stp_file, self.a3[0], self.a3[rounds])
