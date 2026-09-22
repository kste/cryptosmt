"""Pure Python reference implementation of the CHAM-64/128 round function."""

CIPHER_NAME = "cham_py"
WORDSIZE = 16


def rotl(x, r):
    return ((x << r) | (x >> (16 - r))) & 0xFFFF


def round_function(X0, X1, X2, X3, round_nr=0, rk=0):
    if (round_nr + 1) % 2 == 0:
        r1, r0 = 8, 1
    else:
        r1, r0 = 1, 8
    t = ((X0 ^ round_nr) + (rotl(X1, r1) ^ rk)) & 0xFFFF
    X3_next = rotl(t, r0)
    return X1, X2, X3, X3_next
