'''
Created on Dec 10, 2014

@author: ralph
'''

from parser import stpcommands
from ciphers.cipher import AbstractCipher
from ciphers import components

from parser.stpcommands import getStringLeftRotate as rotl


class CHAMCipher(AbstractCipher):
    """
    Represents the differential behaviour of CHAM and can be used
    to find differential characteristics for the given parameters.
    """

    @property
    def name(self):
        return "cham"

    def getFormatString(self):
        """
        Returns the print format.
        """
        return ['X0', 'X1', 'X2', 'X3', 'w']

    def validate_parameters(self, parameters):
        """
        CHAM supports 16-bit and 32-bit wordsize.
        """
        if parameters["wordsize"] not in [16, 32]:
            parameters["wordsize"] = 16

    def setup_variables(self, stp_file, parameters):
        """
        Declare variables for CHAM.
        """
        wordsize = parameters["wordsize"]
        rounds = parameters["rounds"]
        
        self.x0 = self.declare_variable_vector(stp_file, "X0", rounds, wordsize, is_state=True)
        self.x1 = self.declare_variable_vector(stp_file, "X1", rounds, wordsize, is_state=True)
        self.x2 = self.declare_variable_vector(stp_file, "X2", rounds, wordsize, is_state=True)
        self.x3 = self.declare_variable_vector(stp_file, "X3", rounds, wordsize, is_state=True)
        self.x0x1 = self.declare_variable_vector_per_round(stp_file, "X0X1", rounds, wordsize)
        self.w = self.declare_variable_vector_per_round(stp_file, "w", rounds, wordsize, is_weight=True)

        # Ignore MSB
        parameters["ignore_msbs"] = 1

    def apply_round_constraints(self, stp_file, round_nr, parameters):
        """
        Apply CHAM round constraints.
        """
        wordsize = parameters["wordsize"]
        
        if ((round_nr+1) % 2) == 0:    # even rounds
            rot_x1 = 8
            rot_x0 = 1
        else:                   # odd rounds
            rot_x1 = 1
            rot_x0 = 8

        # Temp variable for rotated x1
        x1_rot = f"X1_{round_nr}_rot"
        stpcommands.setupVariables(stp_file, [x1_rot], wordsize)
        components.add_rotation_left(stp_file, x1_rot, self.x1[round_nr], rot_x1, wordsize)

        # X0X1 = (X0 + rot(X1))
        components.add_addition(stp_file, x1_rot, self.x0[round_nr], self.x0x1[round_nr], wordsize)

        # X3_out = rot(X0X1)
        components.add_rotation_left(stp_file, self.x3[round_nr+1], self.x0x1[round_nr], rot_x0, wordsize)

        # Shift states
        components.add_assignment(stp_file, self.x2[round_nr+1], self.x3[round_nr])
        components.add_assignment(stp_file, self.x1[round_nr+1], self.x2[round_nr])
        components.add_assignment(stp_file, self.x0[round_nr+1], self.x1[round_nr])

        # Weight
        command = f"ASSERT({self.w[round_nr]} = ~"
        command += stpcommands.getStringEq(self.x0[round_nr], x1_rot, self.x0x1[round_nr])
        command += ");\n"
        stp_file.write(command)

    def apply_iterative_constraints(self, stp_file, parameters):
        """
        Iterative constraint for CHAM.
        """
        rounds = parameters["rounds"]
        stpcommands.assertVariableValue(stp_file, self.x0[0], self.x0[rounds])
        stpcommands.assertVariableValue(stp_file, self.x1[0], self.x1[rounds])
        stpcommands.assertVariableValue(stp_file, self.x2[0], self.x2[rounds])
        stpcommands.assertVariableValue(stp_file, self.x3[0], self.x3[rounds])
