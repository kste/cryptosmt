'''
Created on Mar 28, 2014

@author: stefan
'''

from parser import stpcommands
from ciphers.cipher import AbstractCipher
from ciphers import components


class SimonCipher(AbstractCipher):
    """
    Represents the differential behaviour of SIMON and can be used
    to find differential characteristics for the given parameters.
    """

    @property
    def name(self):
        return "simon"
    rot_alpha = 8
    rot_beta = 1
    rot_gamma = 2

    def getFormatString(self):
        """
        Returns the print format.
        """
        return ['x', 'y', 'w']

    def write_header(self, stp_file, parameters):
        """
        Custom header for Simon with rotation constants.
        """
        # Replace with custom if set in parameters.
        if "rotationconstants" in parameters and parameters["rotationconstants"]:
            self.rot_alpha = parameters["rotationconstants"][0]
            self.rot_beta = parameters["rotationconstants"][1]
            self.rot_gamma = parameters["rotationconstants"][2]

        header = ("% Input File for STP\n% Simon w={} alpha={} beta={}"
                  " gamma={} rounds={}\n\n\n".format(parameters["wordsize"],
                                                     self.rot_alpha,
                                                     self.rot_beta,
                                                     self.rot_gamma,
                                                     parameters["rounds"]))
        stp_file.write(header)

    def setup_variables(self, stp_file, parameters):
        """
        Declare variables in the STP file.
        """
        wordsize = parameters["wordsize"]
        rounds = parameters["rounds"]
        
        self.x = self.declare_variable_vector(stp_file, "x", rounds, wordsize, is_state=True)
        self.y = self.declare_variable_vector(stp_file, "y", rounds, wordsize, is_state=True)
        self.and_out = self.declare_variable_vector(stp_file, "andout", rounds, wordsize)
        self.w = self.declare_variable_vector_per_round(stp_file, "w", rounds, wordsize, is_weight=True)

    def apply_constraints(self, stp_file, parameters):
        """
        Apply Simon-specific constraints.
        """
        # Standard round loop from AbstractCipher template
        super().apply_constraints(stp_file, parameters)

    def apply_round_constraints(self, stp_file, round_nr, parameters):
        """
        Simon round logic using components.
        """
        wordsize = parameters["wordsize"]
        components.add_simon_round_constraints(stp_file, self.x[round_nr], self.y[round_nr],
                                               self.x[round_nr+1], self.y[round_nr+1],
                                               self.and_out[round_nr], self.w[round_nr], wordsize,
                                               self.rot_alpha, self.rot_beta, self.rot_gamma)

    def apply_iterative_constraints(self, stp_file, parameters):
        """
        Iterative constraint for Simon.
        """
        rounds = parameters["rounds"]
        stpcommands.assertVariableValue(stp_file, self.x[0], self.x[rounds])
        stpcommands.assertVariableValue(stp_file, self.y[0], self.y[rounds])
