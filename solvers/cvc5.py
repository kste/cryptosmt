
import subprocess
import logging
from .solver import AbstractSolver, SolverResult
from parser import parsesolveroutput
from config import PATH_STP

logger = logging.getLogger("cryptosmt")

class CVC5Solver(AbstractSolver):
    def solve(self, stp_file: str) -> SolverResult:
        # Create input file with help of STP
        stp_parameters = [PATH_STP, "--print-back-SMTLIB2", stp_file, "--CVC"]
        logger.debug(f"Generating SMTLIB2 for CVC5 using STP...")
        try:
            input_file = subprocess.check_output(stp_parameters)
        except subprocess.CalledProcessError as e:
            logger.error(f"STP failed to generate SMTLIB2: {e}")
            return SolverResult(False, str(e))

        # CVC5 requires (check-sat) and (get-model) if not present
        if b"(check-sat)" not in input_file:
            input_file += b"\n(check-sat)\n"
        if b"(get-model)" not in input_file:
            input_file += b"\n(get-model)\n"

        cvc5_parameters = [self.path, "--lang", "smt2", "--produce-models", "--bitblast=eager"]
        logger.debug(f"Solving with CVC5...")
        cvc5_process = subprocess.Popen(cvc5_parameters,
                                        stdout=subprocess.PIPE,
                                        stdin=subprocess.PIPE,
                                        stderr=subprocess.PIPE)

        result, err = cvc5_process.communicate(input=input_file)
        decoded_result = result.decode("utf-8")
        
        # Prepend 'sat' if it's missing but CVC5 found a model
        if "(define-fun" in decoded_result and "sat" not in decoded_result:
            decoded_result = "sat\n" + decoded_result
        
        is_sat = self._found_solution(decoded_result)
        return SolverResult(is_sat, decoded_result)

    def parse_characteristic(self, result: SolverResult, cipher, rounds):
        # Bitwuzla uses the same SMTLIB2 output format for models
        return parsesolveroutput.getCharBitwuzlaOutput(result.raw_output, cipher, rounds)
