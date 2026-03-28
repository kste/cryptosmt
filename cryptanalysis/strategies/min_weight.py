
import time
import os
import logging
import random
from typing import Dict, Any, Tuple
from tqdm import tqdm
from concurrent.futures import ProcessPoolExecutor, as_completed

from .base import SearchStrategy
import solvers

logger = logging.getLogger("cryptosmt")

def _solve_min_weight_task(cipher, parameters, weight):
    """
    Independent helper for ProcessPoolExecutor.
    """
    rnd_id = f"{random.randrange(16**10):010x}"
    stp_file = f"tmp/{cipher.name}_minw{weight}_{rnd_id}.stp"
    
    local_params = parameters.copy()
    local_params["sweight"] = weight
    cipher.createSTP(stp_file, local_params)
    
    solver = solvers.get_solver(local_params)
    result = solver.solve(stp_file)
    
    if os.path.isfile(stp_file): os.remove(stp_file)
    return (weight, result.is_sat, result)

class MinWeightStrategy(SearchStrategy):
    def run(self) -> int:
        logger.info(f"Starting search for characteristic with minimal weight")
        logger.info(f"Cipher: {self.cipher.name}, Rounds: {self.parameters['rounds']}, "
                    f"Wordsize: {self.parameters['wordsize']} using {self.parameters['threads']} threads")

        num_threads = self.parameters.get("threads", 1)
        sweight = self.parameters["sweight"]
        endweight = self.parameters["endweight"]
        
        pbar = tqdm(range(sweight, endweight), desc="Searching Weight", unit="w", 
                    disable=self.parameters.get("quiet", False))

        if num_threads <= 1:
            for weight in pbar:
                if self.reached_timelimit(): break
                pbar.set_description(f"Weight {weight}")
                
                local_params = self.parameters.copy()
                local_params["sweight"] = weight
                stp_file = f"tmp/{self.cipher.name}{self.parameters['wordsize']}.stp"
                self.cipher.createSTP(stp_file, local_params)
                
                result = self.solver.solve(stp_file)
                if result.is_sat:
                    pbar.close()
                    return self._process_result(weight, result)
        else:
            with ProcessPoolExecutor(max_workers=num_threads) as executor:
                curr_weight = sweight
                while curr_weight < endweight:
                    if self.reached_timelimit(): break
                    
                    batch_size = num_threads
                    batch = range(curr_weight, min(curr_weight + batch_size, endweight))
                    pbar.set_description(f"Weights {batch.start}-{batch.stop-1}")
                    
                    future_to_weight = {executor.submit(_solve_min_weight_task, self.cipher, self.parameters, w): w for w in batch}
                    
                    batch_results = {}
                    for future in as_completed(future_to_weight):
                        w, is_sat, res = future.result()
                        batch_results[w] = (is_sat, res)
                    
                    for w in sorted(batch_results.keys()):
                        pbar.update(1)
                        is_sat, res = batch_results[w]
                        if is_sat:
                            pbar.close()
                            return self._process_result(w, res)
                    curr_weight += batch_size

        pbar.close()
        logger.info(f"No characteristic found within limit. Total Search Time: {self.get_elapsed_time()}s")
        return endweight

    def _process_result(self, weight, result):
        logger.info(f"Characteristic found! Weight: {weight}, Total Search Time: {self.get_elapsed_time()}s")
        characteristic = self.solver.parse_characteristic(result, self.cipher, self.parameters["rounds"])
        characteristic.printText()

        if self.parameters.get("dot"):
            with open(self.parameters["dot"], "w") as f:
                f.write("digraph graphname {")
                f.write(characteristic.getDOTString())
                f.write("}")
        
        if self.parameters.get("latex"):
            with open(self.parameters["latex"], "w") as f:
                f.write(characteristic.getTexString())
        return weight
