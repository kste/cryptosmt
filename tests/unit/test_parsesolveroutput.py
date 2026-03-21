import pytest
from parser import parsesolveroutput

# Mock cipher object for testing
class MockCipher:
    def __init__(self):
        self.name = "mockcipher"
    
    def getFormatString(self):
        return ["x", "y", "w"]

def test_getCharSTPOutput():
    cipher = MockCipher()
    stp_output = """
ASSERT( weight = 0000000000001010 );
ASSERT( x0 = 0x0100 );
ASSERT( y0 = 0x0444 );
"""
    rounds = 1
    characteristic = parsesolveroutput.getCharSTPOutput(stp_output, cipher, rounds)
    
    assert characteristic.weight == "0000000000001010"
    assert characteristic.characteristic_data["x0"] == "0x0100"
    assert characteristic.characteristic_data["y0"] == "0x0444"

def test_getCharBitwuzlaOutput():
    cipher = MockCipher()
    # Sample Bitwuzla SMT-LIB2 output
    bitwuzla_output = """
(define-fun |x0| () (_ BitVec 16) #x0100)
(define-fun |y0| () (_ BitVec 16) #x0444)
(define-fun |weight| () (_ BitVec 16) #x000a)
"""
    rounds = 1
    characteristic = parsesolveroutput.getCharBitwuzlaOutput(bitwuzla_output, cipher, rounds)
    
    assert characteristic.weight == "0x000a"
    assert characteristic.characteristic_data["x0"] == "0x0100"
    assert characteristic.characteristic_data["y0"] == "0x0444"

def test_getCharBoolectorOutput():
    cipher = MockCipher()
    # Sample Boolector SMT2 output
    boolector_output = """
|x0| 0100
|y0| 0444
|weight| 000a
"""
    rounds = 1
    characteristic = parsesolveroutput.getCharBoolectorOutput(boolector_output, cipher, rounds)
    
    assert characteristic.weight == "0x000a"
    assert characteristic.characteristic_data["x0"] == "0x0100"
    assert characteristic.characteristic_data["y0"] == "0x0444"
