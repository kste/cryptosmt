'''
Created on Apr 3, 2014

@author: stefan
'''

from typing import Dict, Any, List
from parser import parsesolveroutput
from config import (PATH_STP, PATH_BOOLECTOR, PATH_BITWUZLA, PATH_CRYPTOMINISAT, MAX_WEIGHT,
                    MAX_CHARACTERISTICS)
from ciphers.cipher import AbstractCipher

import subprocess
import random
import math
import os
import time
import logging
from tqdm import tqdm

logger = logging.getLogger("cryptosmt")

def computeProbabilityOfDifferentials(cipher: AbstractCipher, parameters: Dict[str, Any]) -> float:
    """
    Computes the probability of the differential by iteratively
    summing up all characteristics of a specific weight using
    a SAT solver.
    """
    rnd_string_tmp = f"{random.randrange(16**30):030x}"
    diff_prob = 0.0
    characteristics_found = 0
    sat_logfile = f"tmp/satlog{rnd_string_tmp}.tmp"

    start_time = time.time()

    logger.info(f"Computing probability for {cipher.name} - Rounds: {parameters['rounds']}")
    
    # Progress bar for weight iterations
    weight_range = range(parameters["sweight"], parameters["endweight"])
    pbar = tqdm(weight_range, desc="Weights", unit="weight", disable=parameters.get("quiet", False))

    try:
        for weight in pbar:
            weight_start_time = time.time()
            parameters["sweight"] = weight
            if reachedTimelimit(start_time, parameters["timelimit"]):
                break

            if os.path.isfile(sat_logfile):
                os.remove(sat_logfile)

            stp_file = f"tmp/{cipher.name}{rnd_string_tmp}.stp"
            cipher.createSTP(stp_file, parameters)

            # Start solver
            sat_process = startSATsolver(stp_file)
            log_file = open(sat_logfile, "w")

            # Find the number of solutions with the SAT solver
            pbar.set_description(f"Weight {weight}")

            # Watch the process and count solutions
            solutions = 0
            while sat_process.poll() is None:
                line = sat_process.stdout.readline().decode("utf-8")
                log_file.write(line)
                if "s SATISFIABLE" in line:
                    solutions += 1
            
            log_file.close()
            
            assert solutions == countSolutionsLogfile(sat_logfile)

            # The encoded CNF contains every solution twice
            solutions //= 2

            # Print result
            diff_prob += math.pow(2, -weight) * solutions
            characteristics_found += solutions
            
            iteration_time = round(time.time() - weight_start_time, 2)
            # Update progress bar stats
            postfix = {"trails": characteristics_found, "time": f"{iteration_time}s"}
            if diff_prob > 0:
                postfix["log2(pr)"] = f"{math.log(diff_prob, 2):.2f}"
            pbar.set_postfix(postfix)

            if solutions > 0:
                current_log_prob = math.log(diff_prob, 2)
                logger.debug(f"Weight {weight}: {solutions} solutions found in {iteration_time}s. "
                             f"Total trails: {characteristics_found}. "
                             f"Current log2(prob): {current_log_prob:.2f}")
    finally:
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

    constantMinWeights = []
    gamma = parameters["sweight"]
    
    logger.info(f"Finding best constants for {cipher.name} (gamma={gamma})")
    
    for beta in range(0, wordsize):
        for alpha in range(0, wordsize):
            weight = 0
            #Filter cases where alpha = beta
            if alpha == beta:
                constantMinWeights.append(0)
                continue
            #Filter symmetric cases
            if beta > alpha:
                constantMinWeights.append(constantMinWeights[alpha * wordsize +
                                                             beta])
                continue
            #Filter gcd(alpha - beta, n) != 1 cases
            if math.gcd(alpha - beta, wordsize) != 1:
                constantMinWeights.append(1)
                continue

            while weight < parameters["endweight"]:
                parameters["rotationconstants"] = [alpha, beta, gamma]

                # Construct problem instance for given parameters
                stp_file = f"tmp/{cipher.name}_{gamma}const.stp"
                cipher.createSTP(stp_file, parameters)

                result = ""
                if parameters["boolector"]:
                    result = solveBoolector(stp_file)
                elif parameters["bitwuzla"]:
                    result = solveBitwuzla(stp_file)
                else:
                    result = solveSTP(stp_file)

                # Check if a characteristic was found
                if foundSolution(result):
                    logger.info(f"Alpha: {alpha} Beta: {beta} Gamma: {gamma} Weight: {weight}")
                    break
                weight += 1
            constantMinWeights.append(weight)
    
    logger.info(f"Constant Min Weights: {constantMinWeights}")
    return constantMinWeights

def findMinWeightCharacteristic(cipher: AbstractCipher, parameters: Dict[str, Any]) -> int:
    """
    Find a characteristic of minimal weight for the cipher
    parameters = [rounds, wordsize, sweight, isIterative, fixedVariables]
    """

    logger.info(f"Starting search for characteristic with minimal weight")
    logger.info(f"Cipher: {cipher.name}, Rounds: {parameters['rounds']}, Wordsize: {parameters['wordsize']}")

    start_time = time.time()

    # Progress bar for weight discovery
    pbar = tqdm(range(parameters["sweight"], parameters["endweight"]), 
                desc="Searching Weight", unit="w", disable=parameters.get("quiet", False))

    found_weight = parameters["sweight"]
    for weight in pbar:
        weight_start_time = time.time()
        found_weight = weight
        if reachedTimelimit(start_time, parameters["timelimit"]):
            break

        pbar.set_description(f"Weight {weight}")
        logger.debug(f"Testing weight {weight}...")

        # Construct problem instance for given parameters
        parameters["sweight"] = weight
        stp_file = f"tmp/{cipher.name}{parameters['wordsize']}.stp"
        cipher.createSTP(stp_file, parameters)

        result = ""
        if parameters["boolector"]:
            result = solveBoolector(stp_file)
        elif parameters["bitwuzla"]:
            result = solveBitwuzla(stp_file)
        else:
            result = solveSTP(stp_file)

        iteration_time = round(time.time() - weight_start_time, 2)
        pbar.set_postfix({"last": f"{iteration_time}s"})

        # Check if a characteristic was found
        if foundSolution(result):
            current_time = round(time.time() - start_time, 2)
            pbar.close()
            logger.info(f"Characteristic found! Weight: {weight}, Time: {current_time}s")
            
            characteristic = ""
            if parameters["boolector"]:
                characteristic = parsesolveroutput.getCharBoolectorOutput(
                    result, cipher, parameters["rounds"])
            elif parameters["bitwuzla"]:
                characteristic = parsesolveroutput.getCharBitwuzlaOutput(
                    result, cipher, parameters["rounds"])
            else:
                characteristic = parsesolveroutput.getCharSTPOutput(
                    result, cipher, parameters["rounds"])

            characteristic.printText()

            if parameters["dot"]:
                with open(parameters["dot"], "w") as dot_file:
                    dot_file.write("digraph graphname {")
                    dot_file.write(characteristic.getDOTString())
                    dot_file.write("}")
                logger.info(f"Wrote .dot to {parameters['dot']}")
                
            if parameters["latex"]:
                with open(parameters["latex"], "w") as tex_file:
                    tex_file.write(characteristic.getTexString())
                logger.info(f"Wrote .tex to {parameters['latex']}")                
            return weight
            
    pbar.close()
    logger.info("No characteristic found within the given weight/time limit.")
    return found_weight


def findAllCharacteristics(cipher: AbstractCipher, parameters: Dict[str, Any]) -> None:
    """
    Outputs all characteristics of a specific weight by excluding
    solutions iteratively.
    """
    rnd_string_tmp = f"{random.randrange(16**30):030x}"
    start_time = time.time()
    total_num_characteristics = 0

    logger.info(f"Finding all characteristics for {cipher.name} - Rounds: {parameters['rounds']}, Weight: {parameters['sweight']}")

    # Using tqdm for counting found characteristics
    pbar = tqdm(desc="Found", unit=" char", disable=parameters.get("quiet", False))

    while not reachedTimelimit(start_time, parameters["timelimit"]) and \
          parameters["sweight"] < parameters["endweight"]:
        iteration_start_time = time.time()
        stp_file = f"tmp/{cipher.name}{rnd_string_tmp}.stp"

        cipher.createSTP(stp_file, parameters)

        result = ""
        if parameters["boolector"]:
            result = solveBoolector(stp_file)
        elif parameters["bitwuzla"]:
            result = solveBitwuzla(stp_file)
        else:
            result = solveSTP(stp_file)

        iteration_time = round(time.time() - iteration_start_time, 2)
        pbar.set_postfix({"last": f"{iteration_time}s"})

        # Check for solution
        if foundSolution(result):
            characteristic = ""
            if parameters["boolector"]:
                characteristic = parsesolveroutput.getCharBoolectorOutput(
                    result, cipher, parameters["rounds"])
            elif parameters["bitwuzla"]:
                characteristic = parsesolveroutput.getCharBitwuzlaOutput(
                    result, cipher, parameters["rounds"])
            else:
                characteristic = parsesolveroutput.getCharSTPOutput(
                    result, cipher, parameters["rounds"])

            # characteristic.printText() # Maybe too noisy for "find all"
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
        logger.info(f"Wrote .dot to {parameters['dot']}")
        
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

def countSolutionsLogfile(logfile_path: str) -> int:
    """
    Count the number of solutions in a CryptoMiniSat Logfile
    """
    with open(logfile_path, "r") as logfile:
        logged_solutions = 0
        for line in logfile:
            if "s SATISFIABLE" in line:
                logged_solutions += 1
        return logged_solutions
    return -1

def startSATsolver(stp_file: str) -> subprocess.Popen:
    """
    Return CryptoMiniSat process started with the given stp_file.
    """
    # Start STP to construct CNF
    logger.debug(f"Running STP to generate CNF from {stp_file}")
    subprocess.check_output([PATH_STP, "--exit-after-CNF", "--output-CNF",
                             stp_file, "--CVC", "--disable-simplifications"])

    # Find the number of solutions with the SAT solver
    sat_params = [PATH_CRYPTOMINISAT, "--maxsol", str(MAX_CHARACTERISTICS),
                  "--verb", "0", "-s", "0", "output_0.cnf"]

    logger.debug(f"Starting SAT solver: {' '.join(sat_params)}")
    sat_process = subprocess.Popen(sat_params, stderr=subprocess.PIPE,
                                   stdout=subprocess.PIPE)

    return sat_process

def solveSTP(stp_file: str) -> str:
    """
    Returns the solution for the given SMT problem using STP.
    """
    stp_parameters = [PATH_STP, stp_file, "--CVC"]
    logger.debug(f"Solving with STP: {' '.join(stp_parameters)}")
    result = subprocess.check_output(stp_parameters)

    return result.decode("utf-8")

def solveBoolector(stp_file: str) -> str:
    """
    Returns the solution for the given SMT problem using boolector.
    """
    # Create input file with help of STP
    stp_parameters = [PATH_STP, "--print-back-SMTLIB2", stp_file, "--CVC"]
    logger.debug(f"Generating SMTLIB2 for Boolector using STP...")
    input_file = subprocess.check_output(stp_parameters)

    boolector_parameters = [PATH_BOOLECTOR, "-x", "-m"]
    logger.debug(f"Solving with Boolector...")
    boolector_process = subprocess.Popen(boolector_parameters,
                                         stdout=subprocess.PIPE,
                                         stdin=subprocess.PIPE)

    result = boolector_process.communicate(input=input_file)[0]
    decoded_result = result.decode("utf-8")

    return decoded_result

def solveBitwuzla(stp_file: str) -> str:
    """
    Returns the solution for the given SMT problem using bitwuzla.
    """
    # Create input file with help of STP
    stp_parameters = [PATH_STP, "--print-back-SMTLIB2", stp_file, "--CVC"]
    logger.debug(f"Generating SMTLIB2 for Bitwuzla using STP...")
    input_file = subprocess.check_output(stp_parameters)

    # Bitwuzla requires (check-sat) and (get-model)
    if b"(check-sat)" not in input_file:
        input_file += b"\n(check-sat)\n"
    if b"(get-model)" not in input_file:
        input_file += b"\n(get-model)\n"

    bitwuzla_parameters = [PATH_BITWUZLA, "-m", "--bv-output-format", "16"]
    logger.debug(f"Solving with Bitwuzla...")
    bitwuzla_process = subprocess.Popen(bitwuzla_parameters,
                                        stdout=subprocess.PIPE,
                                        stdin=subprocess.PIPE,
                                        stderr=subprocess.PIPE)

    result, err = bitwuzla_process.communicate(input=input_file)
    decoded_result = result.decode("utf-8")
    
    # Prepend 'sat' if it's missing but Bitwuzla found a model
    if "(define-fun" in decoded_result and "sat" not in decoded_result:
        decoded_result = "sat\n" + decoded_result
    
    return decoded_result

def foundSolution(solver_result: str) -> bool:
    """
    Check if a solution was found.
    """
    if "unsat" in solver_result:
        return False
    if "sat" in solver_result:
        return True
    if "Valid" in solver_result:
        return False
    if "Invalid" in solver_result:
        return True
    return False
