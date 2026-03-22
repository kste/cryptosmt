import pytest
import os
import re

# This file contains integration tests for searching characteristics of different ciphers.
# They require solvers to be available (typically run in Docker).

def solver_available():
    from config import PATH_STP, PATH_BITWUZLA, PATH_BOOLECTOR
    return any(os.path.exists(p) for p in [PATH_STP, PATH_BITWUZLA, PATH_BOOLECTOR])

@pytest.mark.skipif(not solver_available(), reason="Solver not found (not in docker?)")
@pytest.mark.parametrize("cipher, rounds, wordsize, expected_weight, extra_args", [
    ("simon", 8, 16, 18, []),
    ("simon", 7, 16, 14, []),
    ("speck", 4, 16, 5, []),
    ("speck", 5, 16, 9, []),
    ("skinny", 1, 16, 2, ["--blocksize", "64"]),
])
def test_cipher_find_min_weight(run_cryptosmt, cipher, rounds, wordsize, expected_weight, extra_args):
    """
    Finds the minimum weight characteristic for a given cipher, rounds, and wordsize.
    Mode 0 (default).
    """
    args = ["--cipher", cipher, "--rounds", str(rounds), "--wordsize", str(wordsize)] + extra_args
    result = run_cryptosmt(args)
    
    assert result.returncode == 0
    assert f"Weight: {expected_weight}" in result.stdout
    assert f"INFO: Characteristic found! Weight: {expected_weight}" in result.stdout

@pytest.mark.skipif(not solver_available(), reason="Solver not found")
def test_keccak_challenge(run_cryptosmt):
    """
    Tests finding a preimage for a Keccak challenge.
    """
    yaml_path = "examples/keccak/keccak_2round_challenge.yaml"
    args = ["--inputfile", yaml_path, "--bitwuzla"]
    
    result = run_cryptosmt(args)
    
    assert result.returncode == 0
    # Preimage found is indicated by "Characteristic found!" and weight 0
    assert "Characteristic found!" in result.stdout
    assert "Weight: 0" in result.stdout

@pytest.mark.skipif(not solver_available(), reason="Solver not found")
def test_simon_iterative_search(run_cryptosmt):
    """
    Tests searching for an iterative characteristic of Simon.
    """
    args = ["--cipher", "simon", "--rounds", "4", "--wordsize", "16", "--iterative"]
    result = run_cryptosmt(args)
    
    assert result.returncode == 0
    assert "Weight: 15" in result.stdout
    assert "INFO: Characteristic found! Weight: 15" in result.stdout

@pytest.mark.skipif(not solver_available(), reason="Solver not found")
def test_speck_iterative_search(run_cryptosmt):
    """
    Tests searching for an iterative characteristic of Speck.
    """
    args = ["--cipher", "speck", "--rounds", "3", "--wordsize", "16", "--iterative"]
    result = run_cryptosmt(args)
    
    assert result.returncode == 0
    # Speck-32 3 rounds iterative found weight 18
    assert "Weight: 18" in result.stdout

@pytest.mark.skipif(not solver_available(), reason="Solver not found")
def test_skinny_iterative_search(run_cryptosmt):
    """
    Tests searching for an iterative characteristic of Skinny.
    """
    args = ["--cipher", "skinny", "--rounds", "2", "--wordsize", "16", "--blocksize", "64", "--iterative"]
    result = run_cryptosmt(args)
    
    assert result.returncode == 0
    # Skinny-64 2 rounds iterative found weight 30
    assert "Weight: 30" in result.stdout

@pytest.mark.skipif(not solver_available(), reason="Solver not found")
def test_simon_probability_estimation(run_cryptosmt):
    """
    Tests mode 4 (probability estimation) for Simon-32 13 rounds.
    """
    yaml_path = "examples/simon/simon32_13rounds_diff.yaml"
    args = ["--inputfile", yaml_path, "--endweight", "40", "--bitwuzla"]
    
    result = run_cryptosmt(args)
    
    assert result.returncode == 0
    assert "INFO: Total Trails found: 66" in result.stdout
    assert "INFO: Final Probability (log2): -32.36" in result.stdout
