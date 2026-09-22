"""Pure Python reference implementation of the Alzette 64-bit ARX-box (32-bit words).

Each round corresponds to one Alzette step with round-dependent rotation constants
(31, 24), (17, 17), (0, 31), (24, 16).
"""

CIPHER_NAME = "alzette_py"
WORDSIZE = 32

ALZETTE_ROTS = [
    (31, 24),
    (17, 17),
    (0, 31),
    (24, 16),
]


def rotr(x, r):
    r %= 32
    if r == 0:
        return x
    return ((x >> r) | (x << (32 - r))) & 0xFFFFFFFF


def round_function(x, y, round_nr=0, rc=0xB7E15162):
    r1, r2 = ALZETTE_ROTS[round_nr % 4]
    x = (x + rotr(y, r1)) & 0xFFFFFFFF
    y = y ^ rotr(x, r2)
    x = x ^ rc
    return x, y
