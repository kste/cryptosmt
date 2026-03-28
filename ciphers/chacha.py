'''
Created on Jan 6, 2016

@author: stefan
'''

from parser import stpcommands
from ciphers.cipher import AbstractCipher
from ciphers import components


class ChaChaCipher(AbstractCipher):
    """
    Represents the differential behaviour of the ChaCha stream cipher.
    """

    @property
    def name(self):
        return "chacha"

    def getFormatString(self):
        """
        Returns the print format.
        """
        return ['a0', 'a1', 'a2', 'a3',
                'a4', 'a5', 'a6', 'a7',
                'a8', 'a9', 'a10', 'a11',
                'a12', 'a13', 'a14', 'a15']

    def setup_variables(self, stp_file, parameters):
        """
        Declare variables for ChaCha.
        """
        wordsize = parameters["wordsize"]
        rounds = parameters["rounds"]
        
        self.a = []
        for i in range(16):
            self.a.append(self.declare_variable_vector(stp_file, f"a{i}", rounds, wordsize, is_state=True))
        
        self.w = []
        for i in range(16):
            self.w.append(self.declare_variable_vector_per_round(stp_file, f"w{i}", rounds, wordsize, is_weight=True))
            
        # ChaCha uses modular addition, ignore MSB for weight
        parameters["ignore_msbs"] = 1

    def apply_round_constraints(self, stp_file, round_nr, parameters):
        """
        Apply ChaCha round constraints.
        """
        wordsize = parameters["wordsize"]
        
        if round_nr % 2 == 0:
            # Columnround
            for col in range(4):
                idx = [(i * 4 + 4 * col + col) % 16 for i in range(4)]
                a_in = [self.a[i][round_nr] for i in idx]
                a_out = [self.a[i][round_nr+1] for i in idx]
                w = [self.w[i][round_nr] for i in range(4*col, 4*col+4)]
                components.add_chacha_quarter_round(stp_file, a_in, a_out, w, wordsize)
        else:
            # Rowround
            for row in range(4):
                idx = [(i + row) % 4 + 4 * row for i in range(4)]
                a_in = [self.a[i][round_nr] for i in idx]
                a_out = [self.a[i][round_nr+1] for i in idx]
                w = [self.w[i][round_nr] for i in range(4*row, 4*row+4)]
                components.add_chacha_quarter_round(stp_file, a_in, a_out, w, wordsize)
