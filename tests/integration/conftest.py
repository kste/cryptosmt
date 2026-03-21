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
        
        # Prefer faster solvers if not explicitly specified
        from config import PATH_BITWUZLA, PATH_BOOLECTOR
        if "--bitwuzla" not in args and "--boolector" not in args:
            if os.path.exists(PATH_BITWUZLA):
                cmd.append("--bitwuzla")
            elif os.path.exists(PATH_BOOLECTOR):
                cmd.append("--boolector")
        
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
