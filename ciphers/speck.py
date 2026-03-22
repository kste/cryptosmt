'''
Created on Mar 28, 2014

@author: stefan
'''

from parser import stpcommands
from ciphers.cipher import AbstractCipher

from parser.stpcommands import getStringRightRotate as rotr
from parser.stpcommands import getStringLeftRotate as rotl


class SpeckCipher(AbstractCipher):
    """
    Represents the differential behaviour of SPECK and can be used
    to find differential characteristics for the given parameters.
    """

    @property
    def name(self):
        return "speck"
    rot_alpha = 8
    rot_beta = 3

    def getFormatString(self):
        """
        Returns the print format.
        """
        return ['x', 'y', 'w']

    def write_header(self, stp_file, parameters):
        """
        Custom header for Speck.
        """
        wordsize = parameters["wordsize"]
        if wordsize == 16:
            self.rot_alpha = 7
            self.rot_beta = 2
        elif "rotationconstants" in parameters and parameters["rotationconstants"]:
            self.rot_alpha = parameters["rotationconstants"][0]
            self.rot_beta = parameters["rotationconstants"][1]

        header = ("% Input File for STP\n% Speck w={} alpha={} beta={} "
                  "rounds={}\n\n\n".format(wordsize, self.rot_alpha,
                                           self.rot_beta, parameters["rounds"]))
        stp_file.write(header)

    def setup_variables(self, stp_file, parameters):
        """
        Declare variables in the STP file.
        """
        wordsize = parameters["wordsize"]
        rounds = parameters["rounds"]
        
        self.x = self.declare_variable_vector(stp_file, "x", rounds, wordsize, is_state=True)
        self.y = self.declare_variable_vector(stp_file, "y", rounds, wordsize, is_state=True)
        self.w = self.declare_variable_vector_per_round(stp_file, "w", rounds, wordsize, is_weight=True)
        
        # Speck specific: ignore MSB for weight computation
        parameters["ignore_msbs"] = 1

    def apply_round_constraints(self, stp_file, round_nr, parameters):
        """
        Speck round logic.
        """
        wordsize = parameters["wordsize"]
        self.setupSpeckRound(stp_file, self.x[round_nr], self.y[round_nr], 
                             self.x[round_nr+1], self.y[round_nr+1], 
                             self.w[round_nr], wordsize)

    def apply_iterative_constraints(self, stp_file, parameters):
        """
        Iterative constraint for Speck.
        """
        rounds = parameters["rounds"]
        stpcommands.assertVariableValue(stp_file, self.x[0], self.x[rounds])
        stpcommands.assertVariableValue(stp_file, self.y[0], self.y[rounds])

    def setupSpeckRound(self, stp_file, x_in, y_in, x_out, y_out, w, wordsize):
        """
        Model for differential behaviour of one round SPECK
        """
        command = ""

        #Assert(x_in >>> self.rot_alpha + y_in = x_out)
        command += "ASSERT("
        command += stpcommands.getStringAdd(rotr(x_in, self.rot_alpha, wordsize),
                                            y_in, x_out, wordsize)
        command += ");\n"

        #Assert(x_out xor (y_in <<< self.rot_beta) = x_in)
        command += "ASSERT(" + y_out + " = "
        command += "BVXOR(" + x_out + ","
        command += rotl(y_in, self.rot_beta, wordsize)
        command += "));\n"

        #For weight computation
        command += "ASSERT({0} = ~".format(w)
        command += stpcommands.getStringEq(rotr(x_in, self.rot_alpha, wordsize),
                                           y_in, x_out)
        command += ");\n"

        stp_file.write(command)
        return
