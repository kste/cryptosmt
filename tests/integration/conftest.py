import pytest
import subprocess
import os

@pytest.fixture
def run_cryptosmt():
    """
    Fixture to run cryptosmt.py with the given arguments.
    """
    def _run(args):
        cmd = ["python3", "cryptosmt.py"] + args
        
        # Do not automatically add solvers, let the tool use defaults 
        # or the test provide them.
        
        result = subprocess.run(cmd, capture_output=False, stdout=subprocess.PIPE, stderr=subprocess.STDOUT, text=True)
        return result
    return _run

@pytest.fixture
def has_solver():
    """
    Check if at least one solver is available.
    """
    from config import PATH_STP, PATH_BITWUZLA, PATH_BOOLECTOR
    return any(os.path.exists(p) for p in [PATH_STP, PATH_BITWUZLA, PATH_BOOLECTOR])
