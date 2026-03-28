
import pytest
import time
from cryptanalysis import search
from cryptanalysis.strategies.base import SearchStrategy

def test_reached_timelimit():
    # We can test this via a concrete strategy instance or direct helper if available
    # For now, let's just check if the logic in base.py works
    class MockStrategy(SearchStrategy):
        def run(self): pass
        
    params = {"timelimit": 100}
    strategy = MockStrategy(None, params)
    # Not reached
    assert strategy.reached_timelimit() is False
    
    params = {"timelimit": 0}
    strategy = MockStrategy(None, params)
    # Reached (start_time was a tiny bit ago)
    assert strategy.reached_timelimit() is True

def test_foundSolution():
    # This was moved to solvers
    from solvers.stp import STPSolver
    solver = STPSolver("dummy")
    assert solver._found_solution("sat") is True
    assert solver._found_solution("unsat") is False
