import pytest
import os
import re

# This file contains integration tests for searching characteristics of different ciphers.
# They require solvers to be available (typically run in Docker).

def solver_available():
    from config import PATH_STP, PATH_BITWUZLA, PATH_BOOLECTOR
    return any(os.path.exists(p) for p in [PATH_STP, PATH_BITWUZLA, PATH_BOOLECTOR])

def get_available_solvers():
    from config import PATH_STP, PATH_BITWUZLA, PATH_BOOLECTOR
    available = []
    if os.path.exists(PATH_STP):
        available.append("stp")
    if os.path.exists(PATH_BITWUZLA):
        available.append("bitwuzla")
    if os.path.exists(PATH_BOOLECTOR):
        available.append("boolector")
    return available

@pytest.mark.skipif(not solver_available(), reason="Solver not found (not in docker?)")
@pytest.mark.parametrize("cipher, rounds, wordsize, expected_weight, extra_args", [
    ("simon", 4, 16, 6, []),
    ("simon", 3, 16, 4, []),
    ("speck", 3, 16, 3, []),
    ("speck", 2, 16, 1, []),
    ("skinny", 1, 16, 2, ["--blocksize", "64"]),
    ("present", 2, 64, 4, []),
])
def test_cipher_find_min_weight(run_cryptosmt, cipher, rounds, wordsize, expected_weight, extra_args):
    """
    Finds the minimum weight characteristic for a given cipher, rounds, and wordsize.
    Mode 0 (default).
    """
    args = ["--cipher", cipher, "--rounds", str(rounds), "--wordsize", str(wordsize)] + extra_args
    
    # Use bitwuzla if available for speed
    cmd_args = args.copy()
    if "--bitwuzla" not in cmd_args and "--boolector" not in cmd_args:
        if os.path.exists("config.py") and "PATH_BITWUZLA" in open("config.py").read():
             cmd_args.append("--bitwuzla")

    result = run_cryptosmt(cmd_args)
    
    assert result.returncode == 0
    assert f"Weight: {expected_weight}" in result.stdout
    assert f"INFO: Characteristic found! Weight: {expected_weight}" in result.stdout

@pytest.mark.skipif(len(get_available_solvers()) < 2, reason="Need at least two solvers for consistency check")
@pytest.mark.parametrize("rounds, expected_weight", [
    (2, 2),
    (3, 4),
    (4, 6),
])
def test_simon_solvers_consistency(run_cryptosmt, rounds, expected_weight):
    """
    Check if different solvers return the same minimum weight for Simon.
    """
    solvers = get_available_solvers()
    results = {}
    
    for solver in solvers:
        args = ["--cipher", "simon", "--rounds", str(rounds), "--wordsize", "16"]
        if solver != "stp":
            args.append(f"--{solver}")
            
        result = run_cryptosmt(args)
        assert result.returncode == 0
        
        # Extract weight using regex
        match = re.search(r"Weight: (\d+)", result.stdout)
        assert match, f"Could not find weight in output for {solver}"
        results[solver] = int(match.group(1))
        
    # Verify all solvers found the same weight
    first_solver = solvers[0]
    for solver in solvers[1:]:
        assert results[solver] == results[first_solver], \
            f"Solver mismatch: {first_solver} found {results[first_solver]}, but {solver} found {results[solver]}"
    
    assert results[first_solver] == expected_weight

@pytest.mark.skipif(not solver_available(), reason="Solver not found")
def test_keccak_challenge(run_cryptosmt):
    """
    Tests finding a preimage for a Keccak challenge.
    """
    yaml_path = "examples/keccak/keccak_2round_challenge.yaml"
    args = ["--inputfile", yaml_path, "--bitwuzla"]
    
    result = run_cryptosmt(args)
    
    assert result.returncode == 0
    assert "Characteristic found!" in result.stdout
    assert "Weight: 0" in result.stdout

@pytest.mark.skipif(not solver_available(), reason="Solver not found")
def test_simon_iterative_search(run_cryptosmt):
    """
    Tests searching for an iterative characteristic of Simon.
    """
    args = ["--cipher", "simon", "--rounds", "4", "--wordsize", "16", "--iterative", "--bitwuzla"]
    result = run_cryptosmt(args)
    
    assert result.returncode == 0
    assert "Weight: 15" in result.stdout

@pytest.mark.skipif(not solver_available(), reason="Solver not found")
def test_speck_iterative_search(run_cryptosmt):
    """
    Tests searching for an iterative characteristic of Speck.
    """
    args = ["--cipher", "speck", "--rounds", "2", "--wordsize", "16", "--iterative", "--bitwuzla"]
    result = run_cryptosmt(args)
    
    assert result.returncode == 0
    # Speck-32 2 rounds iterative found weight 13
    assert "Weight: 13" in result.stdout

@pytest.mark.skipif(not solver_available(), reason="Solver not found")
def test_skinny_iterative_search(run_cryptosmt):
    """
    Tests searching for an iterative characteristic of Skinny.
    """
    args = ["--cipher", "skinny", "--rounds", "1", "--wordsize", "16", "--blocksize", "64", "--iterative", "--bitwuzla"]
    result = run_cryptosmt(args)
    
    assert result.returncode == 0
    # Skinny-64 1 round iterative found weight 19
    assert "Weight: 19" in result.stdout

@pytest.mark.skipif(not solver_available(), reason="Solver not found")
def test_simon_probability_estimation(run_cryptosmt):
    """
    Tests mode 4 (probability estimation) for Simon-32.
    Reducing rounds to make it faster.
    """
    # Use 4 rounds for Simon-32, starting weight 6
    # Note: Using explicit --stp because only STP supports solve_and_count
    args = ["--cipher", "simon", "--rounds", "4", "--wordsize", "16", "--mode", "4", "--sweight", "6", "--endweight", "8", "--stp"]
    
    result = run_cryptosmt(args)
    
    assert result.returncode == 0
    # It should find at least one characteristic
    assert "INFO: Total Trails found:" in result.stdout
    assert "INFO: Final Probability (log2):" in result.stdout

@pytest.mark.skipif(not solver_available(), reason="Solver not found")
def test_skinny_related_tweak(run_cryptosmt):
    """
    Tests mode 2 (related-key/tweak) for Skinny.
    """
    args = [
        "--cipher", "skinnyrk", 
        "--rounds", "1", 
        "--wordsize", "64", 
        "--tweaksize", "128", 
        "--keysize", "0",
        "--bitwuzla"
    ]
    result = run_cryptosmt(args)
    
    assert result.returncode == 0
    assert "Weight: 0" in result.stdout
