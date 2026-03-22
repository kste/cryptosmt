
import subprocess
import logging
from .solver import AbstractSolver, SolverResult
from parser import parsesolveroutput
from config import PATH_STP

logger = logging.getLogger("cryptosmt")

class BoolectorSolver(AbstractSolver):
    def solve(self, stp_file: str) -> SolverResult:
        # Create input file with help of STP
        stp_parameters = [PATH_STP, "--print-back-SMTLIB2", stp_file, "--CVC"]
        logger.debug(f"Generating SMTLIB2 for Boolector using STP...")
        input_file = subprocess.check_output(stp_parameters)

        boolector_parameters = [self.path, "-x", "-m"]
        logger.debug(f"Solving with Boolector...")
        boolector_process = subprocess.Popen(boolector_parameters,
                                             stdout=subprocess.PIPE,
                                             stdin=subprocess.PIPE)

        result = boolector_process.communicate(input=input_file)[0]
        decoded_result = result.decode("utf-8")

        is_sat = self._found_solution(decoded_result)
        return SolverResult(is_sat, decoded_result)

    def parse_characteristic(self, result: SolverResult, cipher, rounds):
        return parsesolveroutput.getCharBoolectorOutput(result.raw_output, cipher, rounds)
