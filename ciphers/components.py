
from typing import List, TextIO, Tuple, Any
from parser import stpcommands

def add_4bit_sbox(stp_file: TextIO, sbox: List[int], inputs: List[str], outputs: List[str], weights: List[str]):
    """
    Adds constraints for a 4-bit S-box differential transition.
    """
    assert len(inputs) == 4
    assert len(outputs) == 4
    assert len(weights) == 4
    
    variables = inputs + outputs + weights
    command = stpcommands.add4bitSbox(sbox, variables)
    stp_file.write(command)

def add_4bit_sbox_at_pos(stp_file: TextIO, sbox: List[int], pos: int, 
                         in_var: str, out_var: str, w_var: str):
    """
    Adds constraints for a 4-bit S-box at a specific bit position.
    pos is the index of the nibble (0 is bits 0-3).
    """
    inputs = [f"{in_var}[{4*pos + 3}:{4*pos + 3}]",
              f"{in_var}[{4*pos + 2}:{4*pos + 2}]",
              f"{in_var}[{4*pos + 1}:{4*pos + 1}]",
              f"{in_var}[{4*pos + 0}:{4*pos + 0}]"]
    outputs = [f"{out_var}[{4*pos + 3}:{4*pos + 3}]",
               f"{out_var}[{4*pos + 2}:{4*pos + 2}]",
               f"{out_var}[{4*pos + 1}:{4*pos + 1}]",
               f"{out_var}[{4*pos + 0}:{4*pos + 0}]"]
    weights = [f"{w_var}[{4*pos + 3}:{4*pos + 3}]",
               f"{w_var}[{4*pos + 2}:{4*pos + 2}]",
               f"{w_var}[{4*pos + 1}:{4*pos + 1}]",
               f"{w_var}[{4*pos + 0}:{4*pos + 0}]"]
    add_4bit_sbox(stp_file, sbox, inputs, outputs, weights)

def add_bit_permutation(stp_file: TextIO, input_var: str, output_var: str, permutation: List[int], wordsize: int):
    """
    Adds constraints for a bit-level permutation.
    """
    command = ""
    for i, j in enumerate(permutation):
        command += f"ASSERT({input_var}[{i}:{i}] = {output_var}[{j}:{j}]);\n"
    stp_file.write(command)

def add_xor(stp_file: TextIO, out: str, inputs: List[str]):
    """
    Adds a bitwise XOR constraint for multiple inputs.
    """
    if len(inputs) == 1:
        stp_file.write(f"ASSERT({out} = {inputs[0]});\n")
    else:
        xor_chain = inputs[0]
        for i in range(1, len(inputs)):
            xor_chain = f"BVXOR({xor_chain}, {inputs[i]})"
        stp_file.write(f"ASSERT({out} = {xor_chain});\n")

def add_rotation_left(stp_file: TextIO, out: str, in_var: str, rotation: int, wordsize: int):
    """
    Adds a left rotation constraint.
    """
    rot_str = stpcommands.getStringLeftRotate(in_var, rotation, wordsize)
    stp_file.write(f"ASSERT({out} = {rot_str});\n")

def add_rotation_right(stp_file: TextIO, out: str, in_var: str, rotation: int, wordsize: int):
    """
    Adds a right rotation constraint.
    """
    rot_str = stpcommands.getStringRightRotate(in_var, rotation, wordsize)
    stp_file.write(f"ASSERT({out} = {rot_str});\n")

def add_addition(stp_file: TextIO, in1: str, in2: str, out: str, wordsize: int):
    """
    Adds a modular addition constraint for differential cryptanalysis.
    """
    stp_file.write(f"ASSERT({stpcommands.getStringAdd(in1, in2, out, wordsize)});\n")

def add_and_differential(stp_file: TextIO, in1: str, in2: str, out: str):
    """
    Adds AND-gate differential propagation constraint.
    """
    stp_file.write(f"ASSERT({stpcommands.getStringForAndDifferential(in1, in2, out)} = 0bin0);\n")

def add_simon_round_constraints(stp_file: TextIO, x_in: str, y_in: str, x_out: str, y_out: str, 
                                and_out: str, w: str, wordsize: int, 
                                rot_alpha: int, rot_beta: int, rot_gamma: int):
    """
    Optimized Simon round logic.
    """
    from parser.stpcommands import getStringLeftRotate as rotl
    
    # y[i+1] = x[i]
    stp_file.write(f"ASSERT({y_out} = {x_in});\n")

    x_in_rotalpha = rotl(x_in, rot_alpha, wordsize)
    x_in_rotbeta = rotl(x_in, rot_beta, wordsize)
    
    # getDoubleBits logic
    doublebits = f"({rotl(x_in, rot_beta, wordsize)} & ~{rotl(x_in, rot_alpha, wordsize)} & {rotl(x_in, 2 * rot_alpha - rot_beta, wordsize)})"
    varibits = f"({x_in_rotalpha} | {x_in_rotbeta})"

    # Combined validity check: and_out must be a subset of varibits AND satisfy double-bit rule
    valid_expr = f"(({and_out} & ~{varibits}) | (BVXOR({and_out}, {rotl(and_out, rot_alpha - rot_beta, wordsize)}) & {doublebits}))"
    stp_file.write(f"ASSERT({valid_expr} = 0x{'0' * (wordsize // 4)});\n")

    # If x_in is all 1s, and_out must be even.
    # Fixed syntax: use bitwise expression instead of formula in IF
    stp_file.write(f"ASSERT((IF {x_in} = 0x{'f' * (wordsize // 4)} THEN {and_out}[0:0] ELSE 0bin0 ENDIF) = 0bin0);\n")

    # Assert XORs: x_out = (x_in <<< gamma) ^ y_in ^ and_out
    stp_file.write(f"ASSERT({x_out} = BVXOR({rotl(x_in, rot_gamma, wordsize)}, BVXOR({y_in}, {and_out})));\n")

    # Weight computation
    stp_file.write(f"ASSERT({w} = (IF {x_in} = 0x{'f' * (wordsize // 4)} THEN BVSUB({wordsize},0x{'f' * (wordsize // 4)},0x{'0'*((wordsize // 4) - 1)}1) ELSE BVXOR({varibits}, {doublebits}) ENDIF));\n")

def add_speck_weight(stp_file: TextIO, w: str, x_in_rot: str, y_in: str, x_out: str):
    """
    Weight computation for Speck.
    """
    command = f"ASSERT({w} = ~"
    command += stpcommands.getStringEq(x_in_rot, y_in, x_out)
    command += ");\n"
    stp_file.write(command)

def add_speck_round_constraints(stp_file: TextIO, x_in: str, y_in: str, x_out: str, y_out: str, 
                                 w: str, wordsize: int, rot_alpha: int, rot_beta: int):
    """
    Optimized Speck round logic.
    """
    from parser.stpcommands import getStringRightRotate as rotr
    from parser.stpcommands import getStringLeftRotate as rotl
    
    # x_out = (x_in >>> alpha) + y_in
    stp_file.write(f"ASSERT({stpcommands.getStringAdd(rotr(x_in, rot_alpha, wordsize), y_in, x_out, wordsize)});\n")
    
    # y_out = (y_in <<< beta) ^ x_out
    stp_file.write(f"ASSERT({y_out} = BVXOR({rotl(y_in, rot_beta, wordsize)}, {x_out}));\n")
    
    # Weight computation
    stp_file.write(f"ASSERT({w} = ~")
    stp_file.write(stpcommands.getStringEq(rotr(x_in, rot_alpha, wordsize), y_in, x_out))
    stp_file.write(");\n")

def add_rectangle_sbox(stp_file: TextIO, sbox: List[int], i: int, sc_in: str, sr: str, w: str):
    """
    Vertical bit-slice S-box for Rectangle.
    """
    inputs = [f"{sc_in}[{i + 48}:{i + 48}]",
              f"{sc_in}[{i + 32}:{i + 32}]",
              f"{sc_in}[{i + 16}:{i + 16}]",
              f"{sc_in}[{i + 0}:{i + 0}]"]
    outputs = [f"{sr}[{i + 48}:{i + 48}]",
               f"{sr}[{i + 32}:{i + 32}]",
               f"{sr}[{i + 16}:{i + 16}]",
               f"{sr}[{i + 0}:{i + 0}]"]
    weights = [f"{w}[{i + 48}:{i + 48}]",
               f"{w}[{i + 32}:{i + 32}]",
               f"{w}[{i + 16}:{i + 16}]",
               f"{w}[{i + 0}:{i + 0}]"]
    add_4bit_sbox(stp_file, sbox, inputs, outputs, weights)

def add_midori_mix_columns(stp_file: TextIO, mc: str, sb_out: str):
    """
    MixColumns for Midori (bitwise XOR).
    """
    for col in range(4):
        for bit in range(4):
            offset0 = col*16 + 0 + bit
            offset1 = col*16 + 4 + bit
            offset2 = col*16 + 8 + bit
            offset3 = col*16 + 12 + bit

            stp_file.write(f"ASSERT(BVXOR(BVXOR({mc}[{offset1}:{offset1}], {mc}[{offset2}:{offset2}]), {mc}[{offset3}:{offset3}]) = {sb_out}[{offset0}:{offset0}]);\n")
            stp_file.write(f"ASSERT(BVXOR(BVXOR({mc}[{offset0}:{offset0}], {mc}[{offset2}:{offset2}]), {mc}[{offset3}:{offset3}]) = {sb_out}[{offset1}:{offset1}]);\n")
            stp_file.write(f"ASSERT(BVXOR(BVXOR({mc}[{offset0}:{offset0}], {mc}[{offset1}:{offset1}]), {mc}[{offset3}:{offset3}]) = {sb_out}[{offset2}:{offset2}]);\n")
            stp_file.write(f"ASSERT(BVXOR(BVXOR({mc}[{offset0}:{offset0}], {mc}[{offset1}:{offset1}]), {mc}[{offset2}:{offset2}]) = {sb_out}[{offset3}:{offset3}]);\n")

def add_speckey_round(stp_file: TextIO, x_in: str, y_in: str, x_out: str, y_out: str, w: str, wordsize: int):
    """
    SpecKey round used in Sparx (similar to Speck but different constants).
    """
    from parser.stpcommands import getStringRightRotate as rotr
    from parser.stpcommands import getStringLeftRotate as rotl
    
    # x_out = (x_in >>> 7) + y_in
    stp_file.write(f"ASSERT({stpcommands.getStringAdd(rotr(x_in, 7, wordsize), y_in, x_out, wordsize)});\n")
    # y_out = x_out xor (y_in <<< 2)
    stp_file.write(f"ASSERT({y_out} = BVXOR({x_out}, {rotl(y_in, 2, wordsize)}));\n")
    # Weight
    stp_file.write(f"ASSERT({w} = ~")
    stp_file.write(stpcommands.getStringEq(rotr(x_in, 7, wordsize), y_in, x_out))
    stp_file.write(");\n")

def add_sparx_l_box(stp_file: TextIO, x_in: str, y_in: str, x_out: str, y_out: str, wordsize: int):
    """
    Linear L-box for Sparx.
    """
    from parser.stpcommands import getStringLeftRotate as rotl
    xor_x_y = f"BVXOR({x_in}, {y_in})"
    rot_x_y = rotl(xor_x_y, 8, wordsize)
    stp_file.write(f"ASSERT({x_out} = BVXOR({x_in}, {rot_x_y}));\n")
    stp_file.write(f"ASSERT({y_out} = BVXOR({y_in}, {rot_x_y}));\n")

def add_chaskey_round(stp_file: TextIO, v: List[str], v_out: List[str], w: List[str], wordsize: int, rnd: int):
    """
    Chaskey round logic (Half rounds).
    """
    from parser.stpcommands import getStringRightRotate as rotr
    from parser.stpcommands import getStringLeftRotate as rotl
    
    if (rnd % 2) == 0:
        rot_one, rot_two = 5, 8
    else:
        rot_one, rot_two = 7, 13

    # v0_out = v0 + v1
    # Original file had some weird mapping, let's stick to what worked there:
    # v0_out = v2_in + v3_in
    stp_file.write(f"ASSERT({stpcommands.getStringAdd(v[2], v[3], v_out[0], wordsize)});\n")
    # v1_out = rotl(v1_in, rot_one) ^ rotr(v2_out, 16)
    stp_file.write(f"ASSERT({v_out[1]} = BVXOR({rotl(v[1], rot_one, wordsize)}, {rotr(v_out[2], 16, wordsize)}));\n")
    # v2_out = v1_in + v0_in (rotated by 16)
    stp_file.write(f"ASSERT({stpcommands.getStringAdd(v[1], v[0], rotr(v_out[2], 16, wordsize), wordsize)});\n")
    # v3_out = rotl(v3_in, rot_two) ^ v0_out
    stp_file.write(f"ASSERT({v_out[3]} = BVXOR({rotl(v[3], rot_two, wordsize)}, {v_out[0]}));\n")

    # Weights
    stp_file.write(f"ASSERT({w[0]} = ~{stpcommands.getStringEq(v[1], v[0], rotr(v_out[2], 16, wordsize))});\n")
    stp_file.write(f"ASSERT({w[1]} = ~{stpcommands.getStringEq(v[2], v[3], v_out[0])});\n")

def add_craft_mix_columns(stp_file: TextIO, x: str, y: str):
    """
    Craft MixColumns (nibble-based).
    """
    for j in range(4):
        # y[j] = x[j] ^ x[j+8] ^ x[j+12]
        stp_file.write(f"ASSERT({y}[{4*j+3}:{4*j}] = BVXOR(BVXOR({x}[{4*(8+j)+3}:{4*(8+j)}], {x}[{4*(12+j)+3}:{4*(12+j)}]), {x}[{4*j+3}:{4*j}]));\n")
        # y[j+4] = x[j+4] ^ x[j+12]
        stp_file.write(f"ASSERT({y}[{4*(4+j)+3}:{4*(4+j)}] = BVXOR({x}[{4*(4+j)+3}:{4*(4+j)}], {x}[{4*(12+j)+3}:{4*(12+j)}]));\n")
    # y[8..15] = x[8..15]
    stp_file.write(f"ASSERT({y}[63:32] = {x}[63:32]);\n")

def add_noekeon_theta(stp_file: TextIO, v: List[str], v_out: List[str], wordsize: int):
    """
    Noekeon Theta linear layer.
    """
    from parser.stpcommands import getStringRightRotate as rotr
    from parser.stpcommands import getStringLeftRotate as rotl
    
    in1xorin3 = f"BVXOR({v[1]}, {v[3]})"
    l = f"BVXOR(BVXOR({rotl(in1xorin3, 8, wordsize)}, {in1xorin3}), {rotr(in1xorin3, 8, wordsize)})"
    
    in0xorin2 = f"BVXOR({v[0]}, {v[2]})"
    r = f"BVXOR(BVXOR({rotl(in0xorin2, 8, wordsize)}, {in0xorin2}), {rotr(in0xorin2, 8, wordsize)})"
    
    stp_file.write(f"ASSERT({v_out[0]} = BVXOR({v[0]}, {l}));\n")
    stp_file.write(f"ASSERT({v_out[1]} = BVXOR({v[1]}, {r}));\n")
    stp_file.write(f"ASSERT({v_out[2]} = BVXOR({v[2]}, {l}));\n")
    stp_file.write(f"ASSERT({v_out[3]} = BVXOR({v[3]}, {r}));\n")

def add_assignment(stp_file: TextIO, out: str, in_var: str):
    """
    Adds a simple assignment/equality constraint.
    """
    stp_file.write(f"ASSERT({out} = {in_var});\n")
