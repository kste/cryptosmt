
import pytest
from solvers.solver import SolverResult
import solvers

def test_solver_result():
    res = SolverResult(True, "sat\nx=0x1")
    assert res.is_sat is True
    assert res.raw_output == "sat\nx=0x1"

def test_get_solver_factory():
    params = {"bitwuzla": True}
    solver = solvers.get_solver(params)
    assert isinstance(solver, solvers.bitwuzla.BitwuzlaSolver)
    
    params = {"cvc5": True}
    solver = solvers.get_solver(params)
    assert isinstance(solver, solvers.cvc5.CVC5Solver)
    
    params = {"boolector": True}
    solver = solvers.get_solver(params)
    assert isinstance(solver, solvers.boolector.BoolectorSolver)
    
    params = {"stp": True}
    solver = solvers.get_solver(params)
    assert isinstance(solver, solvers.stp.STPSolver)
    
    # Default
    params = {}
    solver = solvers.get_solver(params)
    assert isinstance(solver, solvers.stp.STPSolver)

def test_solver_solution_check():
    # Test common logic in AbstractSolver
    from solvers.stp import STPSolver
    solver = STPSolver("dummy")
    assert solver._found_solution("sat") is True
    assert solver._found_solution("unsat") is False
    assert solver._found_solution("Invalid") is True
    assert solver._found_solution("Valid") is False
    assert solver._found_solution("something else") is False
