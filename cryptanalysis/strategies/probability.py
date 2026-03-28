
import time
import os
import logging
import random
import math
from typing import Dict, Any, Tuple
from concurrent.futures import ProcessPoolExecutor, as_completed

from .base import SearchStrategy
import solvers

logger = logging.getLogger("cryptosmt")

def _solve_weight_count_task(cipher, parameters, weight, approxmc):
    """
    Independent helper for counting solutions in parallel.
    """
    rnd_id = f"{random.randrange(16**10):010x}"
    stp_file = f"tmp/{cipher.name}_w{weight}_{rnd_id}.stp"
    sat_logfile = f"tmp/satlog_w{weight}_{rnd_id}.tmp"
    
    local_params = parameters.copy()
    local_params["sweight"] = weight
    cipher.createSTP(stp_file, local_params)
    
    solver = solvers.get_solver(local_params)
    solutions = solver.solve_and_count(stp_file, sat_logfile, approxmc=approxmc)
    
    if os.path.isfile(stp_file): os.remove(stp_file)
    if os.path.isfile(sat_logfile): os.remove(sat_logfile)

    return (weight, solutions // 2)

class ProbabilityStrategy(SearchStrategy):
    def run(self) -> float:
        if not hasattr(self.solver, "solve_and_count"):
            logger.error(f"Solver {type(self.solver).__name__} does not support counting solutions.")
            return 0.0

        approxmc = self.parameters.get("approxmc", False)
        num_threads = self.parameters.get("threads", 1)
        
        logger.info(f"Computing probability for {self.cipher.name} - Rounds: {self.parameters['rounds']} "
                    f"using {num_threads} threads (ApproxMC: {approxmc})")
        
        weight_range = range(self.parameters["sweight"], self.parameters["endweight"])
        
        diff_prob = 0.0
        characteristics_found = 0
        weight_results = {}

        try:
            if num_threads > 1:
                with ProcessPoolExecutor(max_workers=num_threads) as executor:
                    future_to_weight = {executor.submit(_solve_weight_count_task, self.cipher, 
                                                       self.parameters, w, approxmc): w for w in weight_range}
                    
                    for future in as_completed(future_to_weight):
                        weight, solutions = future.result()
                        weight_results[weight] = solutions
                        diff_prob += math.pow(2, -weight) * solutions
                        characteristics_found += solutions
                        if self.reporter:
                            self.reporter.update_weight(weight)
                            self.reporter.add_trail(weight, f"Found {solutions} trails", count=solutions, prob=diff_prob)
            else:
                for weight in weight_range:
                    if self.reached_timelimit(): break
                    if self.reporter: self.reporter.update_weight(weight)
                    
                    _, solutions = _solve_weight_count_task(self.cipher, self.parameters, weight, approxmc)
                    weight_results[weight] = solutions
                    diff_prob += math.pow(2, -weight) * solutions
                    characteristics_found += solutions
                    if self.reporter:
                        self.reporter.add_trail(weight, f"Found {solutions} trails", count=solutions, prob=diff_prob)
        finally:
            pass

        self._print_summary(weight_results, characteristics_found, diff_prob)
        return diff_prob

    def _print_summary(self, weight_results, found, prob):
        if prob > 0:
            logger.info("\n" + "="*30)
            logger.info(f"{'Weight':<10} | {'Trails Found':<15}")
            logger.info("-" * 30)
            for w in sorted(weight_results.keys()):
                logger.info(f"{w:<10} | {weight_results[w]:<15}")
            logger.info("="*30)
            logger.info(f"Total Trails found: {found}")
            logger.info(f"Final Probability (log2): {math.log(prob, 2):.2f}")
            logger.info(f"Total Search Time: {self.get_elapsed_time()}s")
        else:
            logger.info(f"No characteristics found. Total Search Time: {self.get_elapsed_time()}s")
