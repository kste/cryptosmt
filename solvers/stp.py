
import subprocess
import logging
import os
from .solver import AbstractSolver, SolverResult
from parser import parsesolveroutput
from config import PATH_CRYPTOMINISAT, MAX_CHARACTERISTICS

logger = logging.getLogger("cryptosmt")

class STPSolver(AbstractSolver):
    def solve(self, stp_file: str) -> SolverResult:
        stp_parameters = [self.path, stp_file, "--CVC"]
        logger.debug(f"Solving with STP: {' '.join(stp_parameters)}")
        try:
            raw_output = subprocess.check_output(stp_parameters).decode("utf-8")
            is_sat = self._found_solution(raw_output)
            return SolverResult(is_sat, raw_output)
        except subprocess.CalledProcessError as e:
            logger.error(f"STP failed with exit code {e.returncode}")
            return SolverResult(False, str(e))

    def parse_characteristic(self, result: SolverResult, cipher, rounds):
        return parsesolveroutput.getCharSTPOutput(result.raw_output, cipher, rounds)

    def solve_and_count(self, stp_file: str, sat_logfile: str) -> int:
        """
        Specialized method for STP + CryptoMiniSat to count solutions.
        """
        # Start STP to construct CNF
        logger.debug(f"Running STP to generate CNF from {stp_file}")
        subprocess.check_output([self.path, "--exit-after-CNF", "--output-CNF",
                                 stp_file, "--CVC", "--disable-simplifications"])

        # Find the number of solutions with the SAT solver
        sat_params = [PATH_CRYPTOMINISAT, "--maxsol", str(MAX_CHARACTERISTICS),
                      "--verb", "0", "-s", "0", "output_0.cnf"]

        logger.debug(f"Starting SAT solver: {' '.join(sat_params)}")
        sat_process = subprocess.Popen(sat_params, stderr=subprocess.PIPE,
                                       stdout=subprocess.PIPE)

        log_file = open(sat_logfile, "w")
        solutions = 0
        while sat_process.poll() is None:
            line = sat_process.stdout.readline().decode("utf-8")
            log_file.write(line)
            if "s SATISFIABLE" in line:
                solutions += 1
        
        log_file.close()
        return solutions
