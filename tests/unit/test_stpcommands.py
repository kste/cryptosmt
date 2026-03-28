
import pytest
import io
from parser import stpcommands

def test_getStringForNonZero():
    variables = ["x0", "y0"]
    wordsize = 16
    # Note: Added spaces around |
    expected = "ASSERT(NOT((x0 | y0) = 0bin0000000000000000));"
    assert stpcommands.getStringForNonZero(variables, wordsize) == expected

def test_blockCharacteristic():
    class MockCharData:
        def __init__(self, data):
            self.characteristic_data = data

    char = MockCharData({"x0": "0x0001", "y0": "0x0002", "z0": "0x0003"})
    output = io.StringIO()
    stpcommands.blockCharacteristic(output, char, 16)
    content = output.getvalue()
    # Now includes z0 because it doesn't start with w, tmp, etc.
    assert "BVXOR(x0, 0x0001)" in content
    assert "BVXOR(y0, 0x0002)" in content
    assert "BVXOR(z0, 0x0003)" in content
    assert "ASSERT(NOT(" in content
    assert "0bin0000000000000000" in content

def test_blockCharacteristic_with_ignore_msbs():
    class MockCharData:
        def __init__(self, data):
            self.characteristic_data = data

    # Case like Speck-32: wordsize 16, ignore_msbs 1
    char = MockCharData({"x0": "0x8001"})
    output = io.StringIO()
    stpcommands.blockCharacteristic(output, char, 16, ignore_msbs=1)
    content = output.getvalue()
    
    # Should use bit slice [14:0] (15 bits)
    # The literal 0x8001 masked with 15 bits is 0x0001 -> 0bin000000000000001
    assert "x0[14:0]" in content
    assert "0bin000000000000001" in content
    # The final zero should also be 15 bits
    assert "0bin000000000000000" in content
    assert "ASSERT(NOT(" in content

def test_blockCharacteristic_bitwidth_consistency():
    class MockCharData:
        def __init__(self, data):
            self.characteristic_data = data

    # wordsize 4, ignore 1 -> 3 bits
    char = MockCharData({"x0": "0xa"}) # 1010
    output = io.StringIO()
    stpcommands.blockCharacteristic(output, char, 4, ignore_msbs=1)
    content = output.getvalue()
    
    # 0xa (1010) masked to 3 bits is 010 (0x2)
    assert "x0[2:0]" in content
    assert "0bin010" in content
    assert "0bin000" in content
