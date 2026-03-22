
from abc import ABC, abstractmethod
from typing import Dict, Any, Optional
import subprocess
import logging
from parser import parsesolveroutput

logger = logging.getLogger("cryptosmt")

class SolverResult:
    def __init__(self, is_sat: bool, raw_output: str):
        self.is_sat = is_sat
        self.raw_output = raw_output

class AbstractSolver(ABC):
    def __init__(self, path: str):
        self.path = path

    @abstractmethod
    def solve(self, stp_file: str) -> SolverResult:
        """
        Solve the given STP file and return a SolverResult.
        """
        pass

    @abstractmethod
    def parse_characteristic(self, result: SolverResult, cipher: Any, rounds: int):
        """
        Parse the characteristic from the solver result.
        """
        pass

    def _found_solution(self, solver_result: str) -> bool:
        """
        Common logic to check if a solution was found.
        """
        if "unsat" in solver_result:
            return False
        if "sat" in solver_result:
            return True
        if "Valid" in solver_result:
            return False
        if "Invalid" in solver_result:
            return True
        return False
