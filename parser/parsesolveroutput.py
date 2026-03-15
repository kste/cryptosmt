'''
Created on Mar 28, 2014

@author: stefan
'''

from cryptanalysis import diffchars
import re


def getCharBitwuzlaOutput(output, cipher, rounds):
    """
    Parse the output of Bitwuzla and construct a characteristic.
    """
    characteristic = {}
    weight = "0"
    # Find wordsize from cipher parameters or assume 16 if not found
    # This is a bit hacky but wordsize is not directly in cipher object sometimes
    # but we can get it from the variable values or just assume it's multiple of 4
    hex_len = 4 # Default

    for row in output.split('\n'):
        # Matches: (define-fun |var_name| () sort value)
        # var_name can be |name| or just name
        # value can be #x..., #b..., or (_ bvVAL SIZE)
        tmp = re.search(r'define-fun\s+\|?([a-zA-Z0-9_]+)\|?\s+\(\)\s+\(_\s+BitVec\s+([0-9]+)\)\s+(#x[a-fA-F0-9]+|#b[01]+|\(_\s+bv[0-9]+\s+[0-9]+\))', row)
        if tmp:
            var_name = tmp.group(1)
            wordsize = int(tmp.group(2))
            var_val_raw = tmp.group(3)
            
            hex_len = wordsize // 4
            
            # Convert to 0x... hex string
            if var_val_raw.startswith("#x"):
                var_value = "0x" + var_val_raw[2:].zfill(hex_len)
            elif var_val_raw.startswith("#b"):
                val_int = int(var_val_raw[2:], 2)
                var_value = "0x" + hex(val_int)[2:].zfill(hex_len)
            else:
                # (_ bvVAL SIZE)
                val_match = re.search(r'bv([0-9]+)', var_val_raw)
                if val_match:
                    val_int = int(val_match.group(1))
                    var_value = "0x" + hex(val_int)[2:].zfill(hex_len)
                else:
                    continue

            if var_name == "weight":
                weight = var_value
            else:
                characteristic[var_name] = var_value

    return diffchars.DifferentialCharacteristic(characteristic,
                                                cipher, rounds, weight)


def getCharBoolectorOutput(output, cipher, rounds):
    """
    Parse the output of Boolector and construct a characteristic.
    """
    characteristic = {}
    weight = "0"
    
    # Try to find wordsize from output or assume default
    hex_len = 4

    for row in output.split('\n'):
        # Handle new SMT-LIB2 format: |var_name| value  OR  var_name value
        # value is typically hex if wordsize > 1
        tmp = re.search(r'\|?([a-zA-Z0-9_]+)\|?\s+([a-fA-F0-9]+)', row)
        if tmp:
            var_name = tmp.group(1)
            var_val_raw = tmp.group(2)
            
            # If it's all 0/1 and long, it might be binary
            # but for Boolector SMT2 output it's usually hex for larger bitvecs
            # or it depends on the version.
            # Let's assume hex for now if it contains non-0/1 or is short
            if all(c in '01' for s in var_val_raw for c in s) and len(var_val_raw) > 16:
                var_value = "0x" + hex(int(var_val_raw, 2))[2:]
            else:
                var_value = "0x" + var_val_raw

            if var_name == "weight":
                weight = var_value
            else:
                characteristic[var_name] = var_value
        
        # Handle old BTOR format: ID VALUE NAME
        elif re.match(r'\d+\s+[a-fA-F0-9]+\s+[a-zA-Z0-9_]+', row):
            parts = row.split()
            var_name = parts[2]
            var_value = "0x" + parts[1]
            if var_name == "weight":
                weight = var_value
            else:
                characteristic[var_name] = var_value

    return diffchars.DifferentialCharacteristic(characteristic,
                                                cipher, rounds, weight)


def getCharSTPOutput(output, cipher, rounds):
    """
    Parse the output of STP and construct a characteristic.
    """
    characteristic = {}
    weight = "0"

    for row in output.split('\n'):
        if re.match(r'ASSERT.*weight', row):
            weight = re.search(r'(?<=ASSERT\( weight = ).*(?= \);)', row).group(0)
        elif re.match(r'ASSERT\(.*\)', row):
            tmp = re.search(r'ASSERT\( ([a-z0-9A-Z]+) = ([a-z0-9A-Z]+)', row)
            var_name = tmp.group(1)
            var_value = tmp.group(2)
            characteristic[var_name] = var_value

    return diffchars.DifferentialCharacteristic(characteristic,
                                                cipher, rounds, weight)
