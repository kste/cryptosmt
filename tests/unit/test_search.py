import pytest
import time
import os
from cryptanalysis import search

def test_reachedTimelimit():
    start_time = time.time()
    # Not reached
    assert search.reachedTimelimit(start_time, 100) is False
    # Reached (simulated by passing an old start_time)
    assert search.reachedTimelimit(start_time - 11, 10) is True
    # No limit
    assert search.reachedTimelimit(start_time - 100, -1) is False

def test_countSolutionsLogfile(tmp_path):
    log_file = tmp_path / "sat.log"
    log_file.write_text("some output\ns SATISFIABLE\nmore output\ns SATISFIABLE\n")
    assert search.countSolutionsLogfile(str(log_file)) == 2
    
    log_file.write_text("UNSAT\n")
    assert search.countSolutionsLogfile(str(log_file)) == 0

def test_foundSolution():
    assert search.foundSolution("sat") is True
    assert search.foundSolution("unsat") is False
    assert search.foundSolution("Valid") is False
    assert search.foundSolution("Invalid") is True
    assert search.foundSolution("random stuff") is False
