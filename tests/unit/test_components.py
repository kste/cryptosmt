
import pytest
from io import StringIO
from ciphers import components

def test_add_xor():
    out = StringIO()
    components.add_xor(out, "x_out", ["in1", "in2"])
    assert out.getvalue() == "ASSERT(x_out = BVXOR(in1, in2));\n"
    
    out = StringIO()
    components.add_xor(out, "x_out", ["in1", "in2", "in3"])
    assert out.getvalue() == "ASSERT(x_out = BVXOR(BVXOR(in1, in2), in3));\n"

def test_add_assignment():
    out = StringIO()
    components.add_assignment(out, "var_out", "var_in")
    assert out.getvalue() == "ASSERT(var_out = var_in);\n"

def test_add_rotation():
    out = StringIO()
    components.add_rotation_left(out, "rot_out", "x", 1, 16)
    # Checks actual STP rotate logic string
    val = out.getvalue()
    assert "ASSERT(rot_out =" in val
    assert "<< 1" in val
    assert ">> 15" in val

def test_add_4bit_sbox_at_pos():
    out = StringIO()
    sbox = [0] * 16
    components.add_4bit_sbox_at_pos(out, sbox, 0, "X", "Y", "W")
    val = out.getvalue()
    # Should generate an ASSERT with bit extractions for nibble 0
    assert "X[3:3]" in val
    assert "Y[0:0]" in val
    assert "W[1:1]" in val
    assert "ASSERT" in val
