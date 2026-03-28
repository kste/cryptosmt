'''
Created on Apr 3, 2014

@author: stefan
'''

from typing import Dict, Any, List, Tuple, Optional
from parser import parsesolveroutput
from config import (PATH_STP, PATH_BOOLECTOR, PATH_BITWUZLA, PATH_CRYPTOMINISAT, MAX_WEIGHT,
                    MAX_CHARACTERISTICS)
from ciphers.cipher import AbstractCipher
import solvers

import subprocess
import random
import math
import os
import time
import logging
from tqdm import tqdm
from concurrent.futures import ProcessPoolExecutor, as_completed

logger = logging.getLogger("cryptosmt")

def solve_weight_task(cipher: AbstractCipher, parameters: Dict[str, Any], weight: int) -> Tuple[int, float]:
    """
    Task for solving a single weight, used for parallel probability estimation.
    Returns (solutions, time_taken)
    """
    start_time = time.time()
    rnd_string_tmp = f"{random.randrange(16**10):010x}"
    stp_file = f"tmp/{cipher.name}_w{weight}_{rnd_string_tmp}.stp"
    sat_logfile = f"tmp/satlog_w{weight}_{rnd_string_tmp}.tmp"
    
    # Update weight in local parameters
    local_params = parameters.copy()
    local_params["sweight"] = weight
    cipher.createSTP(stp_file, local_params)
    
    solver = solvers.get_solver(local_params)
    solutions = solver.solve_and_count(stp_file, sat_logfile)
    
    # Cleanup
    if os.path.isfile(stp_file): os.remove(stp_file)
    if os.path.isfile(sat_logfile): os.remove(sat_logfile)

    return (solutions // 2, time.time() - start_time)

def computeProbabilityOfDifferentials(cipher: AbstractCipher, parameters: Dict[str, Any]) -> float:
    """
    Computes the probability of the differential by iteratively
    summing up all characteristics of a specific weight.
    Parallelized version.
    """
    diff_prob = 0.0
    characteristics_found = 0
    start_time = time.time()
    
    solver = solvers.get_solver(parameters)
    if not hasattr(solver, "solve_and_count"):
        logger.error(f"Solver {type(solver).__name__} does not support counting solutions.")
        return 0.0

    logger.info(f"Computing probability for {cipher.name} - Rounds: {parameters['rounds']} using {parameters['threads']} threads")
    
    weight_range = range(parameters["sweight"], parameters["endweight"])
    pbar = tqdm(total=len(weight_range), desc="Weights", unit="weight", disable=parameters.get("quiet", False))

    num_threads = parameters.get("threads", 1)
    
    if num_threads > 1:
        with ProcessPoolExecutor(max_workers=num_threads) as executor:
            future_to_weight = {executor.submit(solve_weight_task, cipher, parameters, w): w for w in weight_range}
            
            for future in as_completed(future_to_weight):
                weight = future_to_weight[future]
                try:
                    solutions, time_taken = future.result()
                    diff_prob += math.pow(2, -weight) * solutions
                    characteristics_found += solutions
                    
                    pbar.update(1)
                    postfix = {"trails": characteristics_found}
                    if diff_prob > 0:
                        postfix["log2(pr)"] = f"{math.log(diff_prob, 2):.2f}"
                    pbar.set_postfix(postfix)
                except Exception as exc:
                    logger.error(f"Weight {weight} generated an exception: {exc}")
    else:
        # Sequential execution
        for weight in weight_range:
            solutions, time_taken = solve_weight_task(cipher, parameters, weight)
            diff_prob += math.pow(2, -weight) * solutions
            characteristics_found += solutions
            pbar.update(1)
            postfix = {"trails": characteristics_found}
            if diff_prob > 0:
                postfix["log2(pr)"] = f"{math.log(diff_prob, 2):.2f}"
            pbar.set_postfix(postfix)

    pbar.close()
    
    if diff_prob > 0:
        logger.info(f"Total Trails found: {characteristics_found}")
        logger.info(f"Final Probability (log2): {math.log(diff_prob, 2):.2f}")
    else:
        logger.info("No characteristics found.")
        
    return diff_prob


def findBestConstants(cipher: AbstractCipher, parameters: Dict[str, Any]) -> List[int]:
    """
    Search for the optimal differential or linear characteristics.
    Works only for SIMON!
    """
    wordsize = parameters["wordsize"]
    solver = solvers.get_solver(parameters)

    constantMinWeights = []
    gamma = parameters["sweight"]
    
    logger.info(f"Finding best constants for {cipher.name} (gamma={gamma})")
    
    for beta in range(0, wordsize):
        for alpha in range(0, wordsize):
            weight = 0
            if alpha == beta:
                constantMinWeights.append(0)
                continue
            if beta > alpha:
                constantMinWeights.append(constantMinWeights[alpha * wordsize +
                                                             beta])
                continue
            if math.gcd(alpha - beta, wordsize) != 1:
                constantMinWeights.append(1)
                continue

            while weight < parameters["endweight"]:
                parameters["rotationconstants"] = [alpha, beta, gamma]
                stp_file = f"tmp/{cipher.name}_{gamma}const.stp"
                cipher.createSTP(stp_file, parameters)
                result = solver.solve(stp_file)
                if result.is_sat:
                    logger.info(f"Alpha: {alpha} Beta: {beta} Gamma: {gamma} Weight: {weight}")
                    break
                weight += 1
            constantMinWeights.append(weight)
    
    logger.info(f"Constant Min Weights: {constantMinWeights}")
    return constantMinWeights

def solve_min_weight_task(cipher: AbstractCipher, parameters: Dict[str, Any], weight: int) -> Tuple[int, bool, Any]:
    """
    Worker task for minimum weight search.
    Returns (weight, is_sat, result)
    """
    rnd_string_tmp = f"{random.randrange(16**10):010x}"
    stp_file = f"tmp/{cipher.name}_minw{weight}_{rnd_string_tmp}.stp"
    
    local_params = parameters.copy()
    local_params["sweight"] = weight
    cipher.createSTP(stp_file, local_params)
    
    solver = solvers.get_solver(local_params)
    result = solver.solve(stp_file)
    
    if os.path.isfile(stp_file): os.remove(stp_file)
    return (weight, result.is_sat, result)

def findMinWeightCharacteristic(cipher: AbstractCipher, parameters: Dict[str, Any]) -> int:
    """
    Find a characteristic of minimal weight for the cipher.
    Parallelized version.
    """
    logger.info(f"Starting search for characteristic with minimal weight")
    logger.info(f"Cipher: {cipher.name}, Rounds: {parameters['rounds']}, Wordsize: {parameters['wordsize']} using {parameters['threads']} threads")

    start_time = time.time()
    num_threads = parameters.get("threads", 1)
    
    sweight = parameters["sweight"]
    endweight = parameters["endweight"]
    
    if num_threads <= 1:
        # Fast path for sequential
        solver = solvers.get_solver(parameters)
        for weight in range(sweight, endweight):
            if reachedTimelimit(start_time, parameters["timelimit"]): break
            parameters["sweight"] = weight
            stp_file = f"tmp/{cipher.name}{parameters['wordsize']}.stp"
            cipher.createSTP(stp_file, parameters)
            result = solver.solve(stp_file)
            if result.is_sat:
                return _process_found_min_weight(cipher, parameters, weight, result, start_time)
        return endweight

    # Parallel version
    # We check in batches of num_threads to maintain "minimum" guarantee
    current_min_found = None
    best_result = None
    
    with ProcessPoolExecutor(max_workers=num_threads) as executor:
        # We can't just check all weights in parallel because we must find the SMALLEST.
        # But we can check a sliding window.
        curr_weight = sweight
        while curr_weight < endweight:
            if reachedTimelimit(start_time, parameters["timelimit"]): break
            
            # Submit a batch of weights
            batch_size = num_threads
            batch = range(curr_weight, min(curr_weight + batch_size, endweight))
            future_to_weight = {executor.submit(solve_min_weight_task, cipher, parameters, w): w for w in batch}
            
            batch_results = {}
            for future in as_completed(future_to_weight):
                w, is_sat, res = future.result()
                batch_results[w] = (is_sat, res)
            
            # Check batch in order to find SMALLEST weight that is SAT
            for w in sorted(batch_results.keys()):
                is_sat, res = batch_results[w]
                if is_sat:
                    return _process_found_min_weight(cipher, parameters, w, res, start_time)
            
            curr_weight += batch_size
            
    logger.info("No characteristic found within the given weight/time limit.")
    return endweight

def _process_found_min_weight(cipher, parameters, weight, result, start_time):
    current_time = round(time.time() - start_time, 2)
    logger.info(f"Characteristic found! Weight: {weight}, Time: {current_time}s")
    
    solver = solvers.get_solver(parameters)
    characteristic = solver.parse_characteristic(result, cipher, parameters["rounds"])
    characteristic.printText()

    if parameters["dot"]:
        with open(parameters["dot"], "w") as dot_file:
            dot_file.write("digraph graphname {")
            dot_file.write(characteristic.getDOTString())
            dot_file.write("}")
        
    if parameters["latex"]:
        with open(parameters["latex"], "w") as tex_file:
            tex_file.write(characteristic.getTexString())
    return weight


def findAllCharacteristics(cipher: AbstractCipher, parameters: Dict[str, Any]) -> None:
    """
    Outputs all characteristics of a specific weight.
    """
    rnd_string_tmp = f"{random.randrange(16**30):030x}"
    start_time = time.time()
    total_num_characteristics = 0
    solver = solvers.get_solver(parameters)

    logger.info(f"Finding all characteristics for {cipher.name} - Rounds: {parameters['rounds']}, Weight: {parameters['sweight']}")

    pbar = tqdm(desc="Found", unit=" char", disable=parameters.get("quiet", False))

    while not reachedTimelimit(start_time, parameters["timelimit"]) and \
          parameters["sweight"] < parameters["endweight"]:
        iteration_start_time = time.time()
        stp_file = f"tmp/{cipher.name}{rnd_string_tmp}.stp"

        cipher.createSTP(stp_file, parameters)
        result = solver.solve(stp_file)

        iteration_time = round(time.time() - iteration_start_time, 2)
        pbar.set_postfix({"last": f"{iteration_time}s"})

        if result.is_sat:
            characteristic = solver.parse_characteristic(result, cipher, parameters["rounds"])
            parameters["blockedCharacteristics"].append(characteristic)
            total_num_characteristics += 1
            pbar.update(1)
        else:
            logger.info(f"Finished weight {parameters['sweight']}. Total found: {total_num_characteristics}")
            parameters["sweight"] += 1
            total_num_characteristics = 0
            pbar.reset()
            continue

    pbar.close()
    
    if parameters["dot"]:
        with open(parameters["dot"], "w") as dot_file:
            dot_file.write("strict digraph graphname {")
            dot_graph = ""
            for characteristic in parameters["blockedCharacteristics"]:
                dot_graph += characteristic.getDOTString()
            dot_file.write(dot_graph)
            dot_file.write("}")
        
    return

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

def reachedTimelimit(start_time: float, timelimit: int) -> bool:
    """
    Return True if the timelimit was reached.
    """
    if round(time.time() - start_time) >= timelimit and timelimit != -1:
        logger.warning(f"Reached the time limit of {timelimit} seconds")
        return True
    return False
