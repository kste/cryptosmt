"""Custom 3-branch Hybrid ARX + Correlated-AND primitive combining subtraction, addition, and Simon AND."""

CIPHER_NAME = "custom_arx_hybrid"
WORDSIZE = 16


def rotl(x, r):
    return ((x << r) | (x >> (16 - r))) & 0xFFFF


def rotr(x, r):
    return ((x >> r) | (x << (16 - r))) & 0xFFFF


def round_function(a, b, c):
    # 1. Modular subtraction + rotation
    sub_out = (rotr(a, 7) - b) & 0xFFFF
    # 2. Correlated rotation-AND (Simon-style) mixed with rotated subtraction output
    nl_and = rotl(b, 8) & rotl(b, 1)
    mid = rotl(sub_out, 5) ^ nl_and
    # 3. Second modular addition with branch c
    add_out = (mid + c) & 0xFFFF
    a_next = add_out
    b_next = rotl(b, 3) ^ sub_out
    c_next = a ^ c
    return a_next, b_next, c_next
