
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

def add_assignment(stp_file: TextIO, out: str, in_var: str):
    """
    Adds a simple assignment/equality constraint.
    """
    stp_file.write(f"ASSERT({out} = {in_var});\n")
