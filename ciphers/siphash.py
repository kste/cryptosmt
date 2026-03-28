'''
Created on Mar 28, 2014

@author: stefan
'''

from parser import stpcommands
from ciphers.cipher import AbstractCipher
from ciphers import components


class SipHashCipher(AbstractCipher):
    """
    Represents the differential behaviour of SipHash and can be used
    to find differential characteristics for the given parameters.
    """

    @property
    def name(self):
        return "siphash"

    def getFormatString(self):
        return ['m', 'v0', 'v1', 'v2', 'v3', 'w0', 'w1', 'w2', 'w3']

    def setup_variables(self, stp_file, parameters):
        """
        Declare variables for SipHash.
        """
        wordsize = parameters["wordsize"]
        rounds = parameters["rounds"]
        num_messages = parameters.get("nummessages", 1)
        
        # We model rounds * num_messages
        total_rounds = rounds * num_messages
        
        self.v0 = self.declare_variable_vector(stp_file, "v0", total_rounds, wordsize, is_state=True)
        self.v1 = self.declare_variable_vector(stp_file, "v1", total_rounds, wordsize, is_state=True)
        self.v2 = self.declare_variable_vector(stp_file, "v2", total_rounds, wordsize, is_state=True)
        self.v3 = self.declare_variable_vector(stp_file, "v3", total_rounds, wordsize, is_state=True)
        
        # Messages m0, m1...
        self.m = [f"m{i}" for i in range(num_messages)]
        stpcommands.setupVariables(stp_file, self.m, wordsize)
        
        self.w0 = self.declare_variable_vector_per_round(stp_file, "w0", total_rounds, wordsize, is_weight=True)
        self.w1 = self.declare_variable_vector_per_round(stp_file, "w1", total_rounds, wordsize, is_weight=True)
        self.w2 = self.declare_variable_vector_per_round(stp_file, "w2", total_rounds, wordsize, is_weight=True)
        self.w3 = self.declare_variable_vector_per_round(stp_file, "w3", total_rounds, wordsize, is_weight=True)
        
        parameters["ignore_msbs"] = 1

    def apply_constraints(self, stp_file, parameters):
        """
        Custom constraint loop for SipHash to handle message injection properly.
        """
        wordsize = parameters["wordsize"]
        rounds_per_block = parameters["rounds"]
        num_messages = parameters.get("nummessages", 1)
        total_rounds = rounds_per_block * num_messages
        
        # 1. Weight computation
        weight = parameters["sweight"]
        ignore_msbs = parameters.get("ignore_msbs", 0)
        encoding = parameters.get("weightencoding", "bvplus")
        stpcommands.setupWeightComputation(stp_file, weight, self.weight_variables, wordsize, ignore_msbs, encoding)

        # 2. Round logic with message injection
        for block in range(num_messages):
            msg = self.m[block]
            for rnd in range(rounds_per_block):
                curr = block * rounds_per_block + rnd
                v_in = [self.v0[curr], self.v1[curr], self.v2[curr], self.v3[curr]]
                v_out = [self.v0[curr+1], self.v1[curr+1], self.v2[curr+1], self.v3[curr+1]]
                w = [self.w0[curr], self.w1[curr], self.w2[curr], self.w3[curr]]
                
                v_in_round = list(v_in)
                if rnd == 0:
                    v_in_round[3] = f"BVXOR({msg}, {v_in[3]})"
                
                if rnd == (rounds_per_block - 1):
                    import random
                    rid = f"{random.randrange(16**8):08x}"
                    v1_raw = f"sip_v1_raw_{curr}_{rid}"
                    stpcommands.setupVariables(stp_file, [v1_raw], wordsize)
                    v_out_round = [v_out[0], v1_raw, v_out[2], v_out[3]]
                    components.add_siphash_round(stp_file, v_in_round, v_out_round, w, wordsize)
                    stp_file.write(f"ASSERT({v_out[1]} = BVXOR({msg}, {v1_raw}));\n")
                else:
                    components.add_siphash_round(stp_file, v_in_round, v_out, w, wordsize)

        # 3. Message collision search specifics
        stpcommands.assertNonZero(stp_file, self.m, wordsize)
        zero_string = "0bin" + "0" * wordsize
        stpcommands.assertVariableValue(stp_file, self.v0[0], zero_string)
        stpcommands.assertVariableValue(stp_file, self.v1[0], zero_string)
        stpcommands.assertVariableValue(stp_file, self.v2[0], zero_string)
        stpcommands.assertVariableValue(stp_file, self.v3[0], zero_string)
        
        collision_val = f"BVXOR({self.v0[total_rounds]}, BVXOR({self.v1[total_rounds]}, BVXOR({self.v2[total_rounds]}, {self.v3[total_rounds]})))"
        stp_file.write(f"ASSERT({collision_val} = {zero_string});\n")
        
        # 4. Common constraints (Non-zero state, fixed vars, blocking)
        self.apply_common_constraints(stp_file, parameters)

    def apply_round_constraints(self, stp_file, round_nr, parameters):
        pass
