'''
Created on Mar 28, 2014

@author: stefan
'''

from parser import stpcommands
from ciphers.cipher import AbstractCipher
from ciphers import components


class ChasKeyMacHalf(AbstractCipher):
    """
    This class provides a model for the differential behaviour of the
    Chaskey MAC (Half rounds version).
    """

    @property
    def name(self):
        return "chaskeyhalf"

    def getFormatString(self):
        """
        Returns the print format.
        """
        return ['v0', 'v1', 'v2', 'v3', 'w0', 'w1']

    def setup_variables(self, stp_file, parameters):
        """
        Declare variables for Chaskey.
        """
        wordsize = parameters["wordsize"]
        rounds = parameters["rounds"]
        
        self.v0 = self.declare_variable_vector(stp_file, "v0", rounds, wordsize, is_state=True)
        self.v1 = self.declare_variable_vector(stp_file, "v1", rounds, wordsize, is_state=True)
        self.v2 = self.declare_variable_vector(stp_file, "v2", rounds, wordsize, is_state=True)
        self.v3 = self.declare_variable_vector(stp_file, "v3", rounds, wordsize, is_state=True)
        
        self.w0 = self.declare_variable_vector_per_round(stp_file, "w0", rounds, wordsize, is_weight=True)
        self.w1 = self.declare_variable_vector_per_round(stp_file, "w1", rounds, wordsize, is_weight=True)
        
        # Chaskey uses modular addition, ignore MSB for weight
        parameters["ignore_msbs"] = 1

    def apply_round_constraints(self, stp_file, round_nr, parameters):
        """
        Apply Chaskey round logic.
        """
        wordsize = parameters["wordsize"]
        v_in = [self.v0[round_nr], self.v1[round_nr], self.v2[round_nr], self.v3[round_nr]]
        v_out = [self.v0[round_nr+1], self.v1[round_nr+1], self.v2[round_nr+1], self.v3[round_nr+1]]
        w = [self.w0[round_nr], self.w1[round_nr]]
        
        components.add_chaskey_round(stp_file, v_in, v_out, w, wordsize, round_nr)

    def apply_iterative_constraints(self, stp_file, parameters):
        """
        Iterative constraint for Chaskey.
        """
        rounds = parameters["rounds"]
        stpcommands.assertVariableValue(stp_file, self.v0[0], self.v0[rounds])
        stpcommands.assertVariableValue(stp_file, self.v1[0], self.v1[rounds])
        stpcommands.assertVariableValue(stp_file, self.v2[0], self.v2[rounds])
        stpcommands.assertVariableValue(stp_file, self.v3[0], self.v3[rounds])
