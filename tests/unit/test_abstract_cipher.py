
import pytest
from io import StringIO
from ciphers.cipher import AbstractCipher

class MockCipher(AbstractCipher):
    @property
    def name(self): return "mock"
    def getFormatString(self): return []
    def setup_variables(self, stp_file, parameters):
        self.x = self.declare_variable_vector(stp_file, "x", 1, 16, is_state=True)
        self.w = self.declare_variable_vector_per_round(stp_file, "w", 1, 16, is_weight=True)
    def apply_round_constraints(self, stp_file, round_nr, parameters):
        stp_file.write(f"ASSERT({self.x[round_nr]} = {self.x[round_nr+1]});\n")

def test_abstract_cipher_registration():
    cipher = MockCipher()
    params = {"rounds": 1, "wordsize": 16, "sweight": 0}
    # We can't easily call createSTP as it opens a file, but we can test components
    
    out = StringIO()
    cipher.setup_variables(out, params)
    assert "x0,x1: BITVECTOR(16);" in out.getvalue()
    assert "w0: BITVECTOR(16);" in out.getvalue()
    assert "x0" in cipher.state_variables
    assert "x1" in cipher.state_variables
    assert "w0" in cipher.weight_variables

def test_abstract_cipher_common_constraints():
    cipher = MockCipher()
    cipher.state_variables = ["x0"]
    params = {"rounds": 1, "wordsize": 16, "fixedVariables": {"x0": "0x1"}}
    
    out = StringIO()
    cipher.apply_common_constraints(out, params)
    val = out.getvalue()
    assert "ASSERT(NOT(x0 = 0bin0000000000000000));" in val
    assert "ASSERT(x0 = 0x1);" in val

def test_abstract_cipher_blocking():
    cipher = MockCipher()
    cipher.state_variables = ["x0"]
    
    class MockChar:
        def __init__(self, data): self.characteristic_data = data
        
    params = {
        "rounds": 1, 
        "wordsize": 16, 
        "blockedCharacteristics": [MockChar({"x0": "0x1234"})]
    }
    
    out = StringIO()
    # This calls self.get_blocking_constraints
    cipher.apply_common_constraints(out, params)
    val = out.getvalue()
    assert "BVXOR(x0, 0x1234)" in val
    assert "ASSERT(NOT(" in val

def test_speck_blocking_custom():
    from ciphers.speck import SpeckCipher
    cipher = SpeckCipher()
    
    class MockChar:
        def __init__(self, data): self.characteristic_data = data
        
    params = {
        "rounds": 1, 
        "wordsize": 16, 
        "blockedCharacteristics": [MockChar({"x0": "0x8001"})]
    }
    
    out = StringIO()
    cipher.get_blocking_constraints(out, params["blockedCharacteristics"][0], params)
    val = out.getvalue()
    
    # Should ignore MSB (15 bits)
    assert "x0[14:0]" in val
    # 0x8001 & 0x7FFF = 0x0001
    assert "0bin000000000000001" in val
