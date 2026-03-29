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
@pytest.mark.parametrize("cipher, rounds, wordsize, expected_weight, sweight, extra_args", [
    ("simon", 4, 16, 6, 5, []),
    ("simon", 3, 16, 4, 3, []),
    ("speck", 3, 16, 3, 2, []),
    ("speck", 2, 32, 1, 0, []), # Speck-64
    ("speck", 2, 16, 1, 0, []),
    ("skinny", 1, 16, 2, 1, ["--blocksize", "64"]),
    ("present", 2, 64, 4, 3, []),
    # Refactored ciphers
    ("cham", 1, 16, 0, 0, []),
    ("cham", 2, 16, 0, 0, []),
    ("lblock", 1, 32, 0, 0, []),
    ("lblock", 2, 32, 2, 1, []),
    ("twine", 1, 64, 0, 0, []),
    ("twine", 2, 64, 2, 1, []),
    # Newly refactored
    ("rectangle", 1, 16, 2, 1, ["--blocksize", "64"]),
    ("gift", 1, 64, 2, 1, []),
    ("midori", 1, 64, 2, 1, []),
    ("sparx", 1, 16, 5, 4, []),
    ("chaskeyhalf", 2, 32, 0, 0, ["--nummessages", "1"]),
    ("craft", 1, 64, 2, 1, []),
    ("noekeon", 2, 32, 0, 0, []),
    # Stream ciphers / hash functions
    ("chacha", 1, 32, 0, 0, []),
    ("salsa", 1, 32, 0, 0, []),
    ("gimli", 2, 32, 0, 0, []),
    ("siphash", 1, 64, 25, 0, ["--nummessages", "1"]),
    # Keccak with capacity 0 (via input file)
    ("keccakdiff", 1, 8, 2, 0, ["--inputfile", "tests/integration/examples/keccak_cap0_1round.yaml"]),
    ("keccakdiff", 2, 8, 8, 0, ["--inputfile", "tests/integration/examples/keccak_cap0_2rounds.yaml"]),
])
def test_cipher_find_min_weight(run_cryptosmt, cipher, rounds, wordsize, expected_weight, sweight, extra_args):
    """
    Finds the minimum weight characteristic for a given cipher, rounds, and wordsize.
    Mode 0 (default).
    """
    args = ["--cipher", cipher, "--rounds", str(rounds), "--wordsize", str(wordsize), "--sweight", str(sweight)] + extra_args    
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

@pytest.mark.skipif(len(get_available_solvers()) < 2, reason="Need at least two solvers for consistency check")
def test_speck_solvers_consistency(run_cryptosmt):
    """
    Check if different solvers return the same minimum weight for Speck-32 6 rounds.
    Weight for 6 rounds is known to be 13.
    """
    solvers = get_available_solvers()
    results = {}
    rounds = 6
    expected_weight = 13
    
    for solver in solvers:
        args = ["--cipher", "speck", "--rounds", str(rounds), "--wordsize", "16"]
        if solver != "stp":
            args.append(f"--{solver}")
            
        result = run_cryptosmt(args)
        assert result.returncode == 0
        
        match = re.search(r"Weight: (\d+)", result.stdout)
        assert match, f"Could not find weight in output for {solver}"
        results[solver] = int(match.group(1))
        
    first_solver = solvers[0]
    for solver in solvers[1:]:
        assert results[solver] == results[first_solver], \
            f"Solver mismatch for Speck: {first_solver} found {results[first_solver]}, but {solver} found {results[solver]}"
    
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

@pytest.mark.skipif(not os.path.exists("/usr/local/bin/stp"), reason="STP/CryptoMiniSat required for Mode 4")
def test_simon_parallel_probability_consistency(run_cryptosmt):
    """
    Verify that parallel mode 4 gives same results as sequential.
    """
    base_args = ["--cipher", "simon", "--rounds", "4", "--wordsize", "16", "--mode", "4", "--sweight", "6", "--endweight", "8", "--stp"]
    
    # Run sequential
    res_seq = run_cryptosmt(base_args + ["--threads", "1"])
    # Run parallel
    res_par = run_cryptosmt(base_args + ["--threads", "2"])
    
    assert res_seq.returncode == 0
    assert res_par.returncode == 0
    
    # Extract final probability using regex
    def get_prob(stdout):
        match = re.search(r"Final Probability \(log2\): ([-\d.]+)", stdout)
        return match.group(1) if match else None
        
    prob_seq = get_prob(res_seq.stdout)
    prob_par = get_prob(res_par.stdout)
    
    assert prob_seq is not None
    assert prob_seq == prob_par, f"Parallel probability {prob_par} != Sequential probability {prob_seq}"

@pytest.mark.skipif(not solver_available(), reason="Solver not found")
def test_simon_parallel_min_weight_consistency(run_cryptosmt):
    """
    Verify that parallel mode 0 gives same results as sequential.
    """
    base_args = ["--cipher", "simon", "--rounds", "4", "--wordsize", "16", "--bitwuzla"]
    
    # Run sequential
    res_seq = run_cryptosmt(base_args + ["--threads", "1"])
    # Run parallel
    res_par = run_cryptosmt(base_args + ["--threads", "4"])
    
    assert res_seq.returncode == 0
    assert res_par.returncode == 0
    
    def get_weight(stdout):
        match = re.search(r"Weight: (\d+)", stdout)
        return int(match.group(1)) if match else None
        
    w_seq = get_weight(res_seq.stdout)
    w_par = get_weight(res_par.stdout)
    
    assert w_seq is not None
    assert w_seq == w_par, f"Parallel weight {w_par} != Sequential weight {w_seq}"

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

@pytest.mark.skipif(not solver_available(), reason="Solver not found")
def test_simon_find_all_characteristics(run_cryptosmt):
    """
    Tests Mode 2 (findAllCharacteristics) for Simon-32 2 rounds weight 2.
    """
    # Simon-32 2 rounds weight 2 has 128 characteristics (16 base * 8 valid rotations)
    args = ["--cipher", "simon", "--rounds", "2", "--wordsize", "16", "--mode", "2", "--sweight", "2", "--endweight", "3", "--bitwuzla"]
    result = run_cryptosmt(args)
    
    assert result.returncode == 0
    assert "Finished weight 2. Total found: 128" in result.stdout

@pytest.mark.skipif(not solver_available(), reason="Solver not found")
def test_speck_differential_probability(run_cryptosmt):
    """
    Tests Mode 4 (Probability Estimation) for Speck-32 9 rounds differential.
    Based on examples/speck/speck32_9rounds_diff.yaml.
    """
    yaml_path = "examples/speck/speck32_9rounds_diff.yaml"
    args = ["--inputfile", yaml_path, "--stp", "--endweight", "31"]
    result = run_cryptosmt(args)
    
    assert result.returncode == 0
    # This differential has exactly 1 trail of weight 30
    assert "Total Trails found: 1" in result.stdout
    assert "Final Probability (log2): -30.00" in result.stdout

@pytest.mark.skipif(not solver_available(), reason="Solver not found")
def test_simon_find_best_constants(run_cryptosmt):
    """
    Tests Mode 3 (findBestConstants) for a very small wordsize to keep it fast.
    """
    # Test wordsize 4 for speed
    args = ["--cipher", "simon", "--rounds", "2", "--wordsize", "4", "--mode", "3", "--sweight", "0", "--endweight", "2", "--bitwuzla"]
    result = run_cryptosmt(args)
    
    assert result.returncode == 0
    assert "Constant Min Weights:" in result.stdout
    # For wordsize 4, it should output a list of weights
    assert "[" in result.stdout and "]" in result.stdout
