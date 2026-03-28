'''
Created on Jun 28, 2017

@author: ralph
'''

from parser import stpcommands
from ciphers.cipher import AbstractCipher
from ciphers import components


class GiftCipher(AbstractCipher):
    """
    Represents the differential behaviour of GIFT and can be used
    to find differential characteristics for the given parameters.
    """

    @property
    def name(self):
        return "gift"

    def getFormatString(self):
        """
        Returns the print format.
        """
        return ['SC', 'PB', 'w']

    def validate_parameters(self, parameters):
        """
        GIFT supports 64-bit or 128-bit wordsize (blocksize).
        """
        if parameters["wordsize"] not in [64, 128]:
            parameters["wordsize"] = 64

    def setup_variables(self, stp_file, parameters):
        """
        Declare variables for GIFT.
        """
        wordsize = parameters["wordsize"]
        rounds = parameters["rounds"]
        
        self.sc = self.declare_variable_vector(stp_file, "SC", rounds, wordsize, is_state=True)
        self.pb = self.declare_variable_vector_per_round(stp_file, "PB", rounds, wordsize)
        self.w = self.declare_variable_vector_per_round(stp_file, "w", rounds, wordsize, is_weight=True)

    def apply_round_constraints(self, stp_file, round_nr, parameters):
        """
        Apply GIFT round constraints.
        """
        wordsize = parameters["wordsize"]
        s_in = self.sc[round_nr]
        p = self.pb[round_nr]
        s_out = self.sc[round_nr+1]
        w = self.w[round_nr]

        # Substitution Layer
        gift_sbox = [0x1, 0xa, 0x4, 0xc, 0x6, 0xf, 0x3, 0x9, 0x2, 0xd, 0xb, 0x7, 0x5, 0x0, 0x8, 0xe]
        nrOfSboxes = wordsize // 4
        for i in range(nrOfSboxes):
            components.add_4bit_sbox_at_pos(stp_file, gift_sbox, i, s_in, p, w)

        # Permutation Layer
        if wordsize == 64:
            # P(i) mapping from original code
            perm = [0, 5, 10, 15, 12, 1, 6, 11, 8, 13, 2, 7, 4, 9, 14, 3, 
                    16, 21, 26, 31, 28, 17, 22, 27, 24, 29, 18, 23, 20, 25, 30, 19, 
                    32, 37, 42, 47, 44, 33, 38, 43, 40, 45, 34, 39, 36, 41, 46, 35, 
                    48, 53, 58, 63, 60, 49, 54, 59, 56, 61, 50, 55, 52, 57, 62, 51]
            # Wait, original code was: ASSERT(s_out[P(i)] = p[i])
            # So s_out bit P(i) comes from pb bit i.
            # components.add_bit_permutation expects perm[i] = j (bit i -> bit j)
            # Original code: command += "ASSERT({0}[17:17] = {1}[1:1]);\n".format(s_out, p) 
            # This means bit 1 of p moves to bit 17 of s_out. So perm[1] = 17.
            
            # Let's rebuild the perm list from original logic: P(i) = 4*(i/16) + 32*((i/4)%4) + (i+i/4)%4
            # Or just use the explicit mappings from the file.
            for i in range(64):
                # i is input bit (pb), j is output bit (s_out)
                j = (i // 16) * 16 + ((i % 16) * 4) % 16 + (i // 4) % 4
                # Wait, simpler: GIFT-64 permutation is: bit i moves to bit j
                # j = [0, 17, 34, 51, 48, 1, 18, 35, 32, 49, 2, 19, 16, 33, 50, 3, ...]
                # I'll use the hardcoded ones from original file to be 100% sure.
                pass
            
            # Re-implementing correctly based on the original GIFT-64 mapping:
            perm64 = [0] * 64
            for i in range(64):
                perm64[i] = 4 * (i // 16) + 16 * ((i // 4) % 4) + (i % 4)
                # Let's verify one: i=1 -> 4*(0) + 16*(0) + 1 = 1? No, original said bit 1 moves to 17.
                # Let's use the exact mappings from the provided code.
            
            gift64_perm = [0, 17, 34, 51, 48, 1, 18, 35, 32, 49, 2, 19, 16, 33, 50, 3,
                           4, 21, 38, 55, 52, 5, 22, 39, 36, 53, 6, 23, 20, 37, 54, 7,
                           8, 25, 42, 59, 56, 9, 26, 43, 40, 57, 10, 27, 24, 41, 58, 11,
                           12, 29, 46, 63, 60, 13, 30, 47, 44, 61, 14, 31, 28, 45, 62, 15]
            components.add_bit_permutation(stp_file, p, s_out, gift64_perm, wordsize)
            
        elif wordsize == 128:
            gift128_perm = [0, 33, 66, 99, 96, 1, 34, 67, 64, 97, 2, 35, 32, 65, 98, 3,
                            4, 37, 70, 103, 100, 5, 38, 71, 68, 101, 6, 39, 36, 69, 102, 7,
                            8, 41, 74, 107, 104, 9, 42, 75, 72, 105, 10, 43, 40, 73, 106, 11,
                            12, 45, 78, 111, 108, 13, 46, 79, 76, 109, 14, 47, 44, 77, 110, 15,
                            16, 49, 82, 115, 112, 17, 50, 83, 80, 113, 18, 51, 48, 81, 114, 19,
                            20, 53, 86, 119, 116, 21, 54, 87, 84, 117, 22, 55, 52, 85, 118, 23,
                            24, 57, 90, 123, 120, 25, 58, 91, 88, 121, 26, 59, 56, 89, 122, 27,
                            28, 61, 94, 127, 124, 29, 62, 95, 92, 125, 30, 63, 60, 93, 126, 31]
            components.add_bit_permutation(stp_file, p, s_out, gift128_perm, wordsize)

    def apply_iterative_constraints(self, stp_file, parameters):
        """
        Iterative constraint for GIFT.
        """
        rounds = parameters["rounds"]
        stpcommands.assertVariableValue(stp_file, self.sc[0], self.sc[rounds])
