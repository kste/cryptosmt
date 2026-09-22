"""Pure Python reference implementation of the Chaskey 128-bit ARX permutation round (16-bit/32-bit)."""

CIPHER_NAME = "chaskey_py"
WORDSIZE = 16


def rotl(x, r):
    return ((x << r) | (x >> (16 - r))) & 0xFFFF


def round_function(v0, v1, v2, v3):
    v0 = (v0 + v1) & 0xFFFF
    v1 = rotl(v1, 5) ^ v0
    v0 = rotl(v0, 8)
    v2 = (v2 + v3) & 0xFFFF
    v3 = rotl(v3, 8) ^ v2
    v0 = (v0 + v3) & 0xFFFF
    v3 = rotl(v3, 13) ^ v0
    v2 = (v2 + v1) & 0xFFFF
    v1 = rotl(v1, 7) ^ v2
    v2 = rotl(v2, 8)
    return v0, v1, v2, v3
