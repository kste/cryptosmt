'''
Created on Mar 20, 2017

@author: ralph
'''

from parser import stpcommands
from ciphers.cipher import AbstractCipher
from ciphers import components

from parser.stpcommands import getStringRightRotate as rotr
from parser.stpcommands import getStringLeftRotate as rotl

class SPARXCipher(AbstractCipher):
    """
    Represents the differential behaviour of SPARX and can be used
    to find differential characteristics for the given parameters.
    """

    @property
    def name(self):
        return "sparx"
    rounds_per_step = 3

    def getFormatString(self):
        """
        Returns the print format.
        """
        return ['X0', 'X1', 'Y0', 'Y1',
                'X0A0', 'X1A0', 'X0A1', 'X1A1', 'X0A2', 'X1A2',
                'Y0A0', 'Y1A0', 'Y0A1', 'Y1A1', 'Y0A2', 'Y1A2', 'w']

    def setup_variables(self, stp_file, parameters):
        """
        Declare variables for SPARX.
        """
        wordsize = parameters["wordsize"]
        rounds = parameters["rounds"]
        
        self.x0 = self.declare_variable_vector(stp_file, "X0", rounds, wordsize, is_state=True)
        self.x1 = self.declare_variable_vector(stp_file, "X1", rounds, wordsize, is_state=True)
        self.y0 = self.declare_variable_vector(stp_file, "Y0", rounds, wordsize, is_state=True)
        self.y1 = self.declare_variable_vector(stp_file, "Y1", rounds, wordsize, is_state=True)
        
        self.x0a0 = self.declare_variable_vector_per_round(stp_file, "X0A0", rounds, wordsize)
        self.x1a0 = self.declare_variable_vector_per_round(stp_file, "X1A0", rounds, wordsize)
        self.x0a1 = self.declare_variable_vector_per_round(stp_file, "X0A1", rounds, wordsize)
        self.x1a1 = self.declare_variable_vector_per_round(stp_file, "X1A1", rounds, wordsize)
        self.x0a2 = self.declare_variable_vector_per_round(stp_file, "X0A2", rounds, wordsize)
        self.x1a2 = self.declare_variable_vector_per_round(stp_file, "X1A2", rounds, wordsize)
        self.x0l = self.declare_variable_vector_per_round(stp_file, "X0L", rounds, wordsize)
        self.x1l = self.declare_variable_vector_per_round(stp_file, "X1L", rounds, wordsize)
        
        self.y0a0 = self.declare_variable_vector_per_round(stp_file, "Y0A0", rounds, wordsize)
        self.y1a0 = self.declare_variable_vector_per_round(stp_file, "Y1A0", rounds, wordsize)
        self.y0a1 = self.declare_variable_vector_per_round(stp_file, "Y0A1", rounds, wordsize)
        self.y1a1 = self.declare_variable_vector_per_round(stp_file, "Y1A1", rounds, wordsize)
        self.y0a2 = self.declare_variable_vector_per_round(stp_file, "Y0A2", rounds, wordsize)
        self.y1a2 = self.declare_variable_vector_per_round(stp_file, "Y1A2", rounds, wordsize)
        
        self.w = self.declare_variable_vector_per_round(stp_file, "w", rounds, wordsize, is_weight=True)

    def apply_round_constraints(self, stp_file, round_nr, parameters):
        """
        Apply SPARX step constraints.
        """
        wordsize = parameters["wordsize"]
        
        # 3 rounds of SPECKEY for left part
        components.add_speckey_round(stp_file, self.x0[round_nr], self.x1[round_nr], self.x0a0[round_nr], self.x1a0[round_nr], self.w[round_nr], wordsize)
        components.add_speckey_round(stp_file, self.x0a0[round_nr], self.x1a0[round_nr], self.x0a1[round_nr], self.x1a1[round_nr], self.w[round_nr], wordsize)
        components.add_speckey_round(stp_file, self.x0a1[round_nr], self.x1a1[round_nr], self.x0a2[round_nr], self.x1a2[round_nr], self.w[round_nr], wordsize)

        # 3 rounds of SPECKEY for right part
        components.add_speckey_round(stp_file, self.y0[round_nr], self.y1[round_nr], self.y0a0[round_nr], self.y1a0[round_nr], self.w[round_nr], wordsize)
        components.add_speckey_round(stp_file, self.y0a0[round_nr], self.y1a0[round_nr], self.y0a1[round_nr], self.y1a1[round_nr], self.w[round_nr], wordsize)
        components.add_speckey_round(stp_file, self.y0a1[round_nr], self.y1a1[round_nr], self.y0a2[round_nr], self.y1a2[round_nr], self.w[round_nr], wordsize)

        # L-box
        components.add_sparx_l_box(stp_file, self.x0a2[round_nr], self.x1a2[round_nr], self.x0l[round_nr], self.x1l[round_nr], wordsize)

        # x_out = L(A^a(x_in)) xor A^a(y_in)
        components.add_xor(stp_file, self.x0[round_nr+1], [self.x0l[round_nr], self.y0a2[round_nr]])
        components.add_xor(stp_file, self.x1[round_nr+1], [self.x1l[round_nr], self.y1a2[round_nr]])

        # y_out = A^a(x_in)
        components.add_assignment(stp_file, self.y0[round_nr+1], self.x0a2[round_nr])
        components.add_assignment(stp_file, self.y1[round_nr+1], self.x1a2[round_nr])

    def apply_iterative_constraints(self, stp_file, parameters):
        """
        Iterative constraint for SPARX.
        """
        rounds = parameters["rounds"]
        stpcommands.assertVariableValue(stp_file, self.x0[0], self.x0[rounds])
        stpcommands.assertVariableValue(stp_file, self.x1[0], self.x1[rounds])
        stpcommands.assertVariableValue(stp_file, self.y0[0], self.y0[rounds])
        stpcommands.assertVariableValue(stp_file, self.y1[0], self.y1[rounds])
