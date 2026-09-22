"""Pure Python reference implementation of the Simon-32/64 round function."""

CIPHER_NAME = "simon_py"
WORDSIZE = 16


def rotl(x, r):
    return ((x << r) | (x >> (16 - r))) & 0xFFFF


def round_function(x, y, k=0):
    f_x = (rotl(x, 8) & rotl(x, 1)) ^ rotl(x, 2)
    x_next = y ^ f_x ^ k
    y_next = x
    return x_next, y_next
