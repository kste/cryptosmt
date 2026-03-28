'''
Created on Apr 3, 2014

@author: stefan
'''

import logging
from typing import Dict, Any, List

from ciphers.cipher import AbstractCipher
from .strategies.min_weight import MinWeightStrategy
from .strategies.probability import ProbabilityStrategy
from .strategies.all_characteristics import AllCharacteristicsStrategy
from .strategies.best_constants import BestConstantsStrategy

logger = logging.getLogger("cryptosmt")

def computeProbabilityOfDifferentials(cipher: AbstractCipher, parameters: Dict[str, Any]) -> float:
    strategy = ProbabilityStrategy(cipher, parameters)
    return strategy.run()

def findBestConstants(cipher: AbstractCipher, parameters: Dict[str, Any]) -> List[int]:
    strategy = BestConstantsStrategy(cipher, parameters)
    return strategy.run()

def findMinWeightCharacteristic(cipher: AbstractCipher, parameters: Dict[str, Any]) -> int:
    strategy = MinWeightStrategy(cipher, parameters)
    return strategy.run()

def findAllCharacteristics(cipher: AbstractCipher, parameters: Dict[str, Any]) -> None:
    strategy = AllCharacteristicsStrategy(cipher, parameters)
    return strategy.run()

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
