
import time
import os
import logging
import random
from typing import Dict, Any
from tqdm import tqdm

from .base import SearchStrategy

logger = logging.getLogger("cryptosmt")

class AllCharacteristicsStrategy(SearchStrategy):
    def run(self) -> None:
        logger.info(f"Finding all characteristics for {self.cipher.name} - Rounds: {self.parameters['rounds']}, Weight: {self.parameters['sweight']}")
        
        rnd_id = f"{random.randrange(16**10):010x}"
        total_num_characteristics = 0
        pbar = tqdm(desc="Found", unit=" char", disable=self.parameters.get("quiet", False))

        # We must maintain a LOCAL list of blocked characteristics because
        # self.parameters might be shared or modified.
        if "blockedCharacteristics" not in self.parameters:
            self.parameters["blockedCharacteristics"] = []

        while not self.reached_timelimit() and self.parameters["sweight"] < self.parameters["endweight"]:
            iteration_start_time = time.time()
            stp_file = f"tmp/{self.cipher.name}_all_{rnd_id}.stp"

            # createSTP will now include all blockedCharacteristics in the STP file
            self.cipher.createSTP(stp_file, self.parameters)
            result = self.solver.solve(stp_file)

            iteration_time = round(time.time() - iteration_start_time, 2)
            pbar.set_postfix({"last": f"{iteration_time}s"})

            if result.is_sat:
                characteristic = self.solver.parse_characteristic(result, self.cipher, self.parameters["rounds"])
                self.parameters["blockedCharacteristics"].append(characteristic)
                total_num_characteristics += 1
                pbar.update(1)
            else:
                logger.info(f"Finished weight {self.parameters['sweight']}. Total found: {total_num_characteristics}")
                self.parameters["sweight"] += 1
                total_num_characteristics = 0
                pbar.reset()
                continue

        pbar.close()
        logger.info(f"Search complete. Total Search Time: {self.get_elapsed_time()}s")
        
        if self.parameters.get("dot"):
            with open(self.parameters["dot"], "w") as f:
                f.write("strict digraph graphname {")
                dot_graph = "".join(c.getDOTString() for c in self.parameters["blockedCharacteristics"])
                f.write(dot_graph)
                f.write("}")
