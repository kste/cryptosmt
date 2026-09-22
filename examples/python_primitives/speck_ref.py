"""Pure Python reference implementation of the Speck-32/64 round function."""

CIPHER_NAME = "speck_py"
WORDSIZE = 16


def rotr(x, r):
    return ((x >> r) | (x << (16 - r))) & 0xFFFF


def rotl(x, r):
    return ((x << r) | (x >> (16 - r))) & 0xFFFF


def round_function(x, y, k=0):
    x_next = ((rotr(x, 7) + y) & 0xFFFF) ^ k
    y_next = rotl(y, 2) ^ x_next
    return x_next, y_next
