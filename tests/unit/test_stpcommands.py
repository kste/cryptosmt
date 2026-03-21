import pytest
from parser import stpcommands

def test_getStringLeftRotate():
    # Test simple rotation
    assert stpcommands.getStringLeftRotate("x", 2, 16) == "(((x << 2)[15:0]) | ((x >> 14)[15:0]))"
    # Test rotation equal to wordsize (should return value as is)
    assert stpcommands.getStringLeftRotate("x", 16, 16) == "x"
    # Test rotation multiple of wordsize
    assert stpcommands.getStringLeftRotate("x", 0, 16) == "x"
    # Test rotation larger than wordsize
    assert stpcommands.getStringLeftRotate("x", 18, 16) == "(((x << 2)[15:0]) | ((x >> 14)[15:0]))"

def test_getStringRightRotate():
    # Test simple rotation
    assert stpcommands.getStringRightRotate("x", 2, 16) == "(((x >> 2)[15:0]) | ((x << 14)[15:0]))"
    # Test rotation equal to wordsize (should return value as is)
    assert stpcommands.getStringRightRotate("x", 16, 16) == "x"
    # Test rotation multiple of wordsize
    assert stpcommands.getStringRightRotate("x", 0, 16) == "x"
    # Test rotation larger than wordsize
    assert stpcommands.getStringRightRotate("x", 18, 16) == "(((x >> 2)[15:0]) | ((x << 14)[15:0]))"

def test_getStringForVariables():
    variables = ["x0", "x1", "x2"]
    wordsize = 16
    expected = "x0,x1,x2: BITVECTOR(16);"
    assert stpcommands.getStringForVariables(variables, wordsize) == expected

def test_getStringForNonZero():
    variables = ["x0", "y0"]
    wordsize = 16
    expected = "ASSERT(NOT((x0|y0) = 0bin0000000000000000));"
    assert stpcommands.getStringForNonZero(variables, wordsize) == expected

def test_getStringEq():
    a, b, c = "x", "y", "z"
    expected = "(BVXOR(~x, y) & BVXOR(~x, z))"
    assert stpcommands.getStringEq(a, b, c) == expected

def test_getStringForAndDifferential():
    a, b, c = "x", "y", "z"
    expected = "((x & z) | (y & z) | (~z))"
    assert stpcommands.getStringForAndDifferential(a, b, c) == expected
