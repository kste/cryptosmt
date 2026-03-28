
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
    assert "ASSERT" in content
