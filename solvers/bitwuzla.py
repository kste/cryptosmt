
import subprocess
import logging
from .solver import AbstractSolver, SolverResult
from parser import parsesolveroutput
from config import PATH_STP

logger = logging.getLogger("cryptosmt")

class BitwuzlaSolver(AbstractSolver):
    def solve(self, stp_file: str) -> SolverResult:
        # Create input file with help of STP
        stp_parameters = [PATH_STP, "--print-back-SMTLIB2", stp_file, "--CVC"]
        logger.debug(f"Generating SMTLIB2 for Bitwuzla using STP...")
        input_file = subprocess.check_output(stp_parameters)

        # Bitwuzla requires (check-sat) and (get-model)
        if b"(check-sat)" not in input_file:
            input_file += b"\n(check-sat)\n"
        if b"(get-model)" not in input_file:
            input_file += b"\n(get-model)\n"

        bitwuzla_parameters = [self.path, "-m", "--bv-output-format", "16"]
        logger.debug(f"Solving with Bitwuzla...")
        bitwuzla_process = subprocess.Popen(bitwuzla_parameters,
                                            stdout=subprocess.PIPE,
                                            stdin=subprocess.PIPE,
                                            stderr=subprocess.PIPE)

        result, err = bitwuzla_process.communicate(input=input_file)
        decoded_result = result.decode("utf-8")
        
        # Prepend 'sat' if it's missing but Bitwuzla found a model
        if "(define-fun" in decoded_result and "sat" not in decoded_result:
            decoded_result = "sat\n" + decoded_result
        
        is_sat = self._found_solution(decoded_result)
        return SolverResult(is_sat, decoded_result)

    def parse_characteristic(self, result: SolverResult, cipher, rounds):
        return parsesolveroutput.getCharBitwuzlaOutput(result.raw_output, cipher, rounds)
