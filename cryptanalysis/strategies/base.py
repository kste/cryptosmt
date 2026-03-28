
from abc import ABC, abstractmethod
from typing import Dict, Any, List, Optional
import time
import logging
from ciphers.cipher import AbstractCipher
import solvers

logger = logging.getLogger("cryptosmt")

class SearchStrategy(ABC):
    def __init__(self, cipher: AbstractCipher, parameters: Dict[str, Any]):
        self.cipher = cipher
        self.parameters = parameters
        self.start_time = time.time()
        self.solver = solvers.get_solver(parameters)

    @abstractmethod
    def run(self) -> Any:
        """
        Execute the search strategy.
        """
        pass

    def reached_timelimit(self) -> bool:
        """
        Check if the search has exceeded the time limit.
        """
        timelimit = self.parameters.get("timelimit", -1)
        if timelimit != -1 and (time.time() - self.start_time) >= timelimit:
            logger.warning(f"Reached the time limit of {timelimit} seconds")
            return True
        return False

    def get_elapsed_time(self) -> float:
        return round(time.time() - self.start_time, 2)
