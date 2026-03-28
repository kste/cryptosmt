
import subprocess
import logging
import os
import random
import shutil
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
        Uses temporary directories for parallel safety because STP hardcodes output_0.cnf.
        """
        rnd_id = f"{random.randrange(16**8):08x}"
        tmp_dir = f"tmp/stp_{rnd_id}"
        os.makedirs(tmp_dir, exist_ok=True)
        
        # Paths must be absolute or relative to the new working directory
        abs_stp_file = os.path.abspath(stp_file)
        abs_sat_logfile = os.path.abspath(sat_logfile)
        
        # Run STP in the temporary directory
        logger.debug(f"Running STP in {tmp_dir} to generate CNF from {stp_file}")
        try:
            subprocess.check_output([self.path, "--exit-after-CNF", "--output-CNF",
                                     abs_stp_file, "--CVC", "--disable-simplifications"],
                                     cwd=tmp_dir)
            
            # output_0.cnf should now be in tmp_dir
            cnf_file = os.path.join(tmp_dir, "output_0.cnf")
            if not os.path.isfile(cnf_file):
                logger.error(f"CNF file not generated in {tmp_dir}")
                return 0

            # Find the number of solutions with the SAT solver
            sat_params = [PATH_CRYPTOMINISAT, "--maxsol", str(MAX_CHARACTERISTICS),
                          "--verb", "0", "-s", "0", "output_0.cnf"]

            logger.debug(f"Starting SAT solver in {tmp_dir}: {' '.join(sat_params)}")
            sat_process = subprocess.Popen(sat_params, stderr=subprocess.PIPE,
                                           stdout=subprocess.PIPE, cwd=tmp_dir)

            log_file = open(abs_sat_logfile, "w")
            solutions = 0
            while sat_process.poll() is None:
                line = sat_process.stdout.readline().decode("utf-8")
                log_file.write(line)
                if "s SATISFIABLE" in line:
                    solutions += 1
            
            log_file.close()
            return solutions
            
        finally:
            # Cleanup unique directory
            if os.path.exists(tmp_dir):
                shutil.rmtree(tmp_dir)
