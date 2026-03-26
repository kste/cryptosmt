
from typing import List, TextIO, Tuple
from parser import stpcommands

def create_sorter(stp_file: TextIO, inputs: List[str], prefix: str) -> List[str]:
    """
    Creates a sorting network for the given 1-bit inputs.
    Returns a list of 1-bit expressions that are sorted (all 1s before all 0s).
    """
    n = len(inputs)
    if n == 0:
        return []
    if n == 1:
        return inputs
    
    # Pad to power of 2
    next_pow2 = 1 << (n - 1).bit_length()
    padded_inputs = inputs + [f"0bin0"] * (next_pow2 - n)
    
    # Sort in descending order (1s first)
    sorted_bits = _bitonic_sort(stp_file, padded_inputs, False, prefix)
    
    return sorted_bits[:n]

def _bitonic_sort(stp_file: TextIO, inputs: List[str], ascending: bool, prefix: str) -> List[str]:
    n = len(inputs)
    if n <= 1:
        return inputs
    
    mid = n // 2
    left = _bitonic_sort(stp_file, inputs[:mid], True, prefix + "L")
    right = _bitonic_sort(stp_file, inputs[mid:], False, prefix + "R")
    
    return _bitonic_merge(stp_file, left + right, ascending, prefix + "M")

def _bitonic_merge(stp_file: TextIO, inputs: List[str], ascending: bool, prefix: str) -> List[str]:
    n = len(inputs)
    if n <= 1:
        return inputs
    
    mid = n // 2
    outputs = [f"{prefix}_{i}" for i in range(n)]
    stpcommands.setupVariables(stp_file, outputs, 1)
    
    for i in range(mid):
        a, b = inputs[i], inputs[i + mid]
        if ascending:
            stp_file.write(f"ASSERT({outputs[i]} = ({a} & {b}));\n")
            stp_file.write(f"ASSERT({outputs[i + mid]} = ({a} | {b}));\n")
        else:
            stp_file.write(f"ASSERT({outputs[i]} = ({a} | {b}));\n")
            stp_file.write(f"ASSERT({outputs[i + mid]} = ({a} & {b}));\n")
            
    left = _bitonic_merge(stp_file, outputs[:mid], ascending, prefix + "mL")
    right = _bitonic_merge(stp_file, outputs[mid:], ascending, prefix + "mR")
    return left + right

def create_totalizer(stp_file: TextIO, inputs: List[str], prefix: str) -> List[str]:
    """
    Creates a Totalizer (unary adder) for the given 1-bit inputs.
    Returns a list of 1-bit variables representing the unary sum.
    """
    n = len(inputs)
    if n == 0:
        return []
    if n == 1:
        return inputs
    
    mid = n // 2
    left = create_totalizer(stp_file, inputs[:mid], prefix + "L")
    right = create_totalizer(stp_file, inputs[mid:], prefix + "R")
    
    n1 = len(left)
    n2 = len(right)
    out_vars = [f"{prefix}_{i}" for i in range(n1 + n2)]
    stpcommands.setupVariables(stp_file, out_vars, 1)
    
    for k in range(n1 + n2):
        clauses = []
        # Case 1: at least k+1 bits from left
        if k < n1:
            clauses.append(left[k])
        # Case 2: at least k+1 bits from right
        if k < n2:
            clauses.append(right[k])
        # Case 3: i+1 bits from left, j+1 bits from right s.t. (i+1)+(j+1) >= k+1
        # smallest such pairs are i+j = k-1
        for i in range(n1):
            j = k - i - 1
            if 0 <= j < n2:
                clauses.append(f"({left[i]} & {right[j]})")
        
        if clauses:
            stp_file.write(f"ASSERT({out_vars[k]} = ({' | '.join(clauses)}));\n")
            
    return out_vars

def add_weight_constraint(stp_file: TextIO, bits: List[str], weight: int, prefix: str, encoding: str, equal: bool = True):
    """
    Adds a weight constraint using the specified encoding.
    """
    if not bits:
        if weight == 0: return
        stp_file.write("ASSERT(0bin0 = 0bin1);\n")
        return

    if encoding == "sorter":
        sorted_bits = create_sorter(stp_file, bits, prefix)
    elif encoding == "totalizer":
        sorted_bits = create_totalizer(stp_file, bits, prefix)
    else:
        raise ValueError(f"Unknown encoding: {encoding}")

    n = len(sorted_bits)
    if equal:
        if weight > 0:
            stp_file.write(f"ASSERT({sorted_bits[weight - 1]} = 0bin1);\n")
        if weight < n:
            stp_file.write(f"ASSERT({sorted_bits[weight]} = 0bin0);\n")
    else:
        if weight < n:
            stp_file.write(f"ASSERT({sorted_bits[weight]} = 0bin0);\n")
