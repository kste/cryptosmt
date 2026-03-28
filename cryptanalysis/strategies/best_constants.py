
import math
import logging
from typing import Dict, Any, List

from .base import SearchStrategy

logger = logging.getLogger("cryptosmt")

class BestConstantsStrategy(SearchStrategy):
    def run(self) -> List[int]:
        """
        Search for the optimal differential or linear characteristics.
        Works only for SIMON!
        """
        wordsize = self.parameters["wordsize"]
        constantMinWeights = []
        gamma = self.parameters["sweight"]
        
        logger.info(f"Finding best constants for {self.cipher.name} (gamma={gamma})")
        
        for beta in range(0, wordsize):
            for alpha in range(0, wordsize):
                weight = 0
                if alpha == beta:
                    constantMinWeights.append(0)
                    continue
                if beta > alpha:
                    constantMinWeights.append(constantMinWeights[alpha * wordsize + beta])
                    continue
                if math.gcd(alpha - beta, wordsize) != 1:
                    constantMinWeights.append(1)
                    continue

                while weight < self.parameters["endweight"]:
                    if self.reached_timelimit(): break
                    
                    self.parameters["rotationconstants"] = [alpha, beta, gamma]
                    stp_file = f"tmp/{self.cipher.name}_{gamma}const.stp"
                    self.cipher.createSTP(stp_file, self.parameters)
                    
                    result = self.solver.solve(stp_file)
                    if result.is_sat:
                        logger.info(f"Alpha: {alpha} Beta: {beta} Gamma: {gamma} Weight: {weight}")
                        break
                    weight += 1
                constantMinWeights.append(weight)
        
        logger.info(f"Constant Min Weights: {constantMinWeights}")
        logger.info(f"Search complete. Total Search Time: {self.get_elapsed_time()}s")
        return constantMinWeights
