'''
Created on Mar 28, 2014

Provides functions for constructing the input file for STP.
@author: stefan
'''

import itertools
from typing import List, Dict, TextIO, Any

def blockCharacteristic(stpfile: TextIO, characteristic: Any, wordsize: int, ignore_msbs: int = 0) -> None:
    """
    Adds an constraint to the stp stpfile that blocks the given characteristic.
    Optimized to use fewer bitwise ORs.
    """
    char_vars = []
    # We want to block based on the state variables.
    # We exclude weight variables (usually start with 'w')
    for var, value in characteristic.characteristic_data.items():
        if var.startswith('w'): 
            continue
        if value == "none": 
            continue
        
        if ignore_msbs > 0 and wordsize > ignore_msbs:
            # Block only non-ignored bits
            new_bits = wordsize - ignore_msbs
            mask = (1 << new_bits) - 1
            try:
                val_int = int(value.replace("0x", "").replace("#x", ""), 16)
                masked_val = val_int & mask
                # hex_val must have exact bit width for the XOR to work if we used slices
                # STP usually expects bitwidth to match. 
                # If we use var[14:0] it's 15 bits. 0x0000 might be seen as 16 bits.
                bin_val = f"0bin{masked_val:0{new_bits}b}"
                char_vars.append(f"BVXOR({var}[{new_bits-1}:0], {bin_val})")
            except ValueError:
                char_vars.append(f"BVXOR({var}, {value})")
        else:
            char_vars.append(f"BVXOR({var}, {value})")

    if char_vars:
        # Group variables to reduce the depth of the OR tree
        while len(char_vars) > 1:
            new_vars = []
            for i in range(0, len(char_vars), 2):
                if i + 1 < len(char_vars):
                    new_vars.append(f"({char_vars[i]} | {char_vars[i+1]})")
                else:
                    new_vars.append(char_vars[i])
            char_vars = new_vars
            
        final_bits = wordsize - ignore_msbs
        stpfile.write(f"ASSERT(NOT({char_vars[0]} = 0bin{'0' * final_bits}));\n")
    return


def setupQuery(stpfile: TextIO) -> None:
    """
    Adds the query and counterexample commands to the stp stpfile.
    """
    stpfile.write("QUERY(FALSE);\n")
    stpfile.write("COUNTEREXAMPLE;\n")
    return


def setupVariables(stpfile: TextIO, variables: List[str], wordsize: int) -> None:
    """
    Adds a list of variables to the stp stpfile.
    """
    if not variables: return
    stpfile.write(getStringForVariables(variables, wordsize) + '\n')
    return


def assertVariableValue(stpfile: TextIO, a: str, b: str) -> None:
    """
    Adds an assert that a = b to the stp stpfile.
    """
    stpfile.write(f"ASSERT({a} = {b});\n")
    return


def getStringForVariables(variables: List[str], wordsize: int) -> str:
    """
    Takes as input the variable name, number of variables and the wordsize
    and constructs for instance a string of the form:
    x00, x01, ..., x30: BITVECTOR(wordsize);
    """
    command = ",".join(variables)
    command += f": BITVECTOR({wordsize});"
    return command


def assertNonZero(stpfile: TextIO, variables: List[str], wordsize: int) -> None:
    stpfile.write(getStringForNonZero(variables, wordsize) + '\n')
    return


def getStringForNonZero(variables: List[str], wordsize: int) -> str:
    """
    Asserts that no all-zero characteristic is allowed.
    Optimized by grouping ORs.
    """
    if not variables:
        return ""
    
    v_list = variables.copy()
    while len(v_list) > 1:
        new_vars = []
        for i in range(0, len(v_list), 2):
            if i + 1 < len(v_list):
                new_vars.append(f"({v_list[i]} | {v_list[i+1]})")
            else:
                new_vars.append(v_list[i])
        v_list = new_vars
        
    command = f"ASSERT(NOT({v_list[0]} = 0bin{'0' * wordsize}));"
    return command


def setupWeightComputation(stpfile: TextIO, weight: int, p: List[str], wordsize: int, ignoreMSBs: int = 0, encoding: str = "bvplus") -> None:
    """
    Assert that weight is equal to the sum of the hamming weight of p.
    """
    stpfile.write("weight: BITVECTOR(16);\n")
    binary_weight = bin(weight)[2:].zfill(16)
    stpfile.write(f"ASSERT(weight = 0bin{binary_weight});\n")

    if encoding in ["sorter", "totalizer"]:
        from . import encodings
        bits = []
        for var in p:
            for bit in range(wordsize - ignoreMSBs):
                bits.append(f"{var}[{bit}:{bit}]")
        encodings.add_weight_constraint(stpfile, bits, weight, "w_enc", encoding, equal=True)
    else:
        stpfile.write(getWeightString(p, wordsize, ignoreMSBs) + "\n")
    return


def limitWeight(stpfile: TextIO, weight: int, p: List[str], wordsize: int, ignoreMSBs: int = 0, encoding: str = "bvplus") -> None:
    """
    Adds the weight computation and assertion to the stp stpfile.
    """
    stpfile.write("limitWeight: BITVECTOR(16);\n")
    binary_weight = bin(weight)[2:].zfill(16)
    
    if encoding in ["sorter", "totalizer"]:
        from . import encodings
        bits = []
        for var in p:
            for bit in range(wordsize - ignoreMSBs):
                bits.append(f"{var}[{bit}:{bit}]")
        encodings.add_weight_constraint(stpfile, bits, weight, "w_limit", encoding, equal=False)
    else:
        stpfile.write(getWeightString(p, wordsize, ignoreMSBs, "limitWeight") + "\n")
        stpfile.write(f"ASSERT(BVLE(limitWeight, 0bin{binary_weight}));\n")
    return

def setupWeightComputationSum(stpfile: TextIO, weight: int, p: List[str], wordsize: int, ignoreMSBs: int = 0, encoding: str = "bvplus") -> None:
    """
    Assert that weight is equal to the sum of p.
    """
    stpfile.write("weight: BITVECTOR(16);\n")
    binary_weight = bin(weight)[2:].zfill(16)
    stpfile.write(f"ASSERT(weight = 0bin{binary_weight});\n")

    if encoding in ["sorter", "totalizer"]:
        from . import encodings
        bits = []
        for var in p:
            for bit in range(wordsize - ignoreMSBs):
                bits.append(f"{var}[{bit}:{bit}]")
        encodings.add_weight_constraint(stpfile, bits, weight, "w_sum_enc", encoding, equal=True)
    else:
        round_sum = ",".join(p)
        if len(p) > 1:
            stpfile.write(f"ASSERT(weight = BVPLUS(16,{round_sum}));\n")
        else:
            stpfile.write(f"ASSERT(weight = {round_sum});\n")
    return


def getWeightString(variables: List[str], wordsize: int, ignoreMSBs: int = 0, weightVariable: str = "weight") -> str:
    """
    Asserts that the weight is equal to the hamming weight of the
    given variables.
    """
    command = f"ASSERT(({weightVariable} = BVPLUS(16,"
    for var in variables:
        tmp = "0bin00000000@(BVPLUS(8, "
        for bit in range(wordsize - ignoreMSBs):
            tmp += f"0bin0000000@({var}[{bit}:{bit}]),"
        if (wordsize - ignoreMSBs) == 1:
            tmp += "0bin0,"
        command += tmp[:-1] + ")),"
    if len(variables):
        command += "0bin0000000000000000,"
    command = command[:-1]
    command += ")));"

    return command


def getStringEq(a: str, b: str, c: str) -> str:
    command = f"(BVXOR(~{a}, {b}) & BVXOR(~{a}, {c}))"
    return command


def getStringAdd(a: str, b: str, c: str, wordsize: int) -> str:
    command = f"(((BVXOR((~{a} << 1)[{wordsize - 1}:0], ({b} << 1)[{wordsize - 1}:0])"
    command += f"& BVXOR((~{a} << 1)[{wordsize - 1}:0], ({c} << 1)[{wordsize - 1}:0]))"
    command += f" & BVXOR({a}, BVXOR({b}, BVXOR({c}, ({b} << 1)[{wordsize - 1}:0]))))"
    command += f" = 0bin{'0' * wordsize})"
    return command

def getStringForAndDifferential(a: str, b: str, c: str) -> str:
    """
    AND = valid(x,y,out) = (x and out) or (y and out) or (not out)
    """
    command = f"(({a} & {c}) | ({b} & {c}) | (~{c}))"
    return command


def getStringLeftRotate(value: str, rotation: int, wordsize: int) -> str:
    if rotation % wordsize == 0:
        return f"{value}"
    command = f"((({value} << {rotation % wordsize})[{wordsize - 1}:0]) | (({value} >> {(wordsize - rotation) % wordsize})[{wordsize - 1}:0]))"

    return command


def getStringRightRotate(value: str, rotation: int, wordsize: int) -> str:
    if rotation % wordsize == 0:
        return f"{value}"
    command = f"((({value} >> {rotation % wordsize})[{wordsize - 1}:0]) | (({value} << {(wordsize - rotation) % wordsize})[{wordsize - 1}:0]))"
    return command

def add4bitSbox(sbox: List[int], variables: List[str]) -> str:
    """
    Adds the constraints for the S-box and the weight.
    """
    assert(len(sbox) == 16)
    assert(len(variables) == 12)

    DDT = [[0]*16 for i in range(16)]
    for a in range(16):
        for b in range(16):
            DDT[a ^ b][sbox[a] ^ sbox[b]] += 1

    trails = []
    for input_diff in range(16):
        for output_diff in range(16):
            if DDT[input_diff][output_diff] != 0:
                tmp = []
                tmp.append((input_diff >> 3) & 1)
                tmp.append((input_diff >> 2) & 1)
                tmp.append((input_diff >> 1) & 1)
                tmp.append((input_diff >> 0) & 1)
                tmp.append((output_diff >> 3) & 1)
                tmp.append((output_diff >> 2) & 1)
                tmp.append((output_diff >> 1) & 1)
                tmp.append((output_diff >> 0) & 1)
                if DDT[input_diff][output_diff] == 2:
                    tmp += [0, 1, 1, 1]
                elif DDT[input_diff][output_diff] == 4:
                    tmp += [0, 0, 1, 1]
                elif DDT[input_diff][output_diff] == 8:
                    tmp += [0, 0, 0, 1]
                elif DDT[input_diff][output_diff] == 16:
                    tmp += [0, 0, 0, 0]
                trails.append(tmp)

    cnf = ""
    for prod in itertools.product([0, 1], repeat=len(trails[0])):
        if list(prod) not in trails:
            expr = ["~" if x == 1 else "" for x in list(prod)]
            clause = ""
            for literal in range(12):
                clause += f"{expr[literal]}{variables[literal]} | "
            cnf += f"({clause[:-2]}) &"

    return f"ASSERT({cnf[:-2]} = 0bin1);\n"
