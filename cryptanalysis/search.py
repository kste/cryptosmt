'''
Created on Apr 3, 2014

@author: stefan
'''

import logging
from typing import Dict, Any, List
from rich.live import Live
import threading

from ciphers.cipher import AbstractCipher
from .strategies.min_weight import MinWeightStrategy
from .strategies.probability import ProbabilityStrategy
from .strategies.all_characteristics import AllCharacteristicsStrategy
from .strategies.best_constants import BestConstantsStrategy
from .reporter import SearchReporter

logger = logging.getLogger("cryptosmt")

def _run_with_reporter(strategy_class, cipher, parameters):
    """
    Helper to run a strategy with the rich reporter in a separate thread.
    This ensures the Live UI stays responsive even during long solver calls.
    """
    if parameters.get("quiet"):
        strategy = strategy_class(cipher, parameters)
        return strategy.run()
        
    reporter = SearchReporter(parameters)
    strategy = strategy_class(cipher, parameters, reporter=reporter)
    
    # We'll store the result here
    result_container = {}

    def search_thread():
        try:
            result_container["result"] = strategy.run()
        except Exception as e:
            result_container["error"] = e

    if not parameters.get("is_interactive"):
        # Fallback for non-interactive: simple run
        return strategy.run()

    t = threading.Thread(target=search_thread)
    t.start()

    layout = reporter.get_layout()
    with Live(layout, refresh_per_second=4) as live:
        # Link reporter update to the live object
        def update_display():
            live.update(reporter.get_layout())
        reporter.update_display = update_display

        while t.is_alive():
            t.join(0.1)
            # Periodic update of footer elapsed time
            live.update(reporter.get_layout())

    if "error" in result_container:
        raise result_container["error"]
        
    return result_container.get("result")

def computeProbabilityOfDifferentials(cipher: AbstractCipher, parameters: Dict[str, Any]) -> float:
    return _run_with_reporter(ProbabilityStrategy, cipher, parameters)

def findBestConstants(cipher: AbstractCipher, parameters: Dict[str, Any]) -> List[int]:
    return _run_with_reporter(BestConstantsStrategy, cipher, parameters)

def findMinWeightCharacteristic(cipher: AbstractCipher, parameters: Dict[str, Any]) -> int:
    return _run_with_reporter(MinWeightStrategy, cipher, parameters)

def findAllCharacteristics(cipher: AbstractCipher, parameters: Dict[str, Any]) -> None:
    return _run_with_reporter(AllCharacteristicsStrategy, cipher, parameters)

def searchCharacteristics(cipher: AbstractCipher, parameters: Dict[str, Any]) -> None:
    """
    Searches for differential characteristics of minimal weight
    for an increasing number of rounds.
    """
    while True:
        logger.info(f"Number of rounds: {parameters['rounds']}")
        parameters["sweight"] = findMinWeightCharacteristic(cipher, parameters)
        parameters["rounds"] = parameters["rounds"] + 1
    return
