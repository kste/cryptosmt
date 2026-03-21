import pytest
import os
import re

# This file contains integration tests for searching characteristics of different ciphers.
# They require solvers to be available (typically run in Docker).

def solver_available():
    from config import PATH_STP, PATH_BITWUZLA, PATH_BOOLECTOR
    return any(os.path.exists(p) for p in [PATH_STP, PATH_BITWUZLA, PATH_BOOLECTOR])

@pytest.mark.skipif(not solver_available(), reason="Solver not found (not in docker?)")
@pytest.mark.parametrize("cipher, rounds, wordsize, expected_weight", [
    ("simon", 8, 16, 18),
    ("simon", 7, 16, 14),
    ("speck", 4, 16, 5),
])
def test_cipher_find_min_weight(run_cryptosmt, cipher, rounds, wordsize, expected_weight):
    """
    Finds the minimum weight characteristic for a given cipher, rounds, and wordsize.
    Mode 0 (default).
    """
    args = ["--cipher", cipher, "--rounds", str(rounds), "--wordsize", str(wordsize)]
    result = run_cryptosmt(args)
    
    assert result.returncode == 0
    assert f"Weight: {expected_weight}" in result.stdout
    assert f"INFO: Characteristic found! Weight: {expected_weight}" in result.stdout

@pytest.mark.skipif(not solver_available(), reason="Solver not found")
def test_simon_iterative_search(run_cryptosmt):
    """
    Tests searching for an iterative characteristic of Simon.
    Reducing to 4 rounds for speed.
    """
    # Simon-32 iterative 4 rounds finds weight 15
    args = ["--cipher", "simon", "--rounds", "4", "--wordsize", "16", "--iterative"]
    result = run_cryptosmt(args)
    
    assert result.returncode == 0
    assert "Weight: 15" in result.stdout
    assert "INFO: Characteristic found! Weight: 15" in result.stdout

@pytest.mark.skipif(not solver_available(), reason="Solver not found")
def test_simon_probability_estimation(run_cryptosmt):
    """
    Tests mode 4 (probability estimation) for Simon-32 13 rounds.
    We limit the search to weight 37 to ensure it finishes very fast.
    """
    yaml_path = "examples/simon/simon32_13rounds_diff.yaml"
    # --endweight 38 means it will search weights 36, 37, 38, 39
    # Use bitwuzla for speed
    args = ["--inputfile", yaml_path, "--endweight", "40", "--bitwuzla"]
    
    result = run_cryptosmt(args)
    
    assert result.returncode == 0
    # From dry run: weight 37 ends with 5 total trails found
    assert "INFO: Total Trails found: 66" in result.stdout
    # Probability at weight 37 should be ~ -34.41
    assert "INFO: Final Probability (log2): -32.36" in result.stdout
