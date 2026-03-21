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

    while not reachedTimelimit(start_time, parameters["timelimit"]) and \
        parameters["sweight"] < parameters["endweight"]:

        if os.path.isfile(sat_logfile):
            os.remove(sat_logfile)

        stp_file = f"tmp/{cipher.name}{rnd_string_tmp}.stp"
        cipher.createSTP(stp_file, parameters)

        # Start solver
        sat_process = startSATsolver(stp_file)
        log_file = open(sat_logfile, "w")

        # Find the number of solutions with the SAT solver
        print(f"Finding all trails of weight {parameters['sweight']}")

        # Watch the process and count solutions
        solutions = 0
        while sat_process.poll() is None:
            line = sat_process.stdout.readline().decode("utf-8")
            log_file.write(line)
            if "s SATISFIABLE" in line:
                solutions += 1
            if solutions % 100 == 0:
                print(f"\tSolutions: {solutions // 2}\r", end="")

        log_file.close()
        print(f"\tSolutions: {solutions // 2}")

        assert solutions == countSolutionsLogfile(sat_logfile)

        # The encoded CNF contains every solution twice
        solutions //= 2

        # Print result
        diff_prob += math.pow(2, -parameters["sweight"]) * solutions
        characteristics_found += solutions
        if diff_prob > 0.0:
            #print("\tSolutions: {}".format(solutions))
            print(f"\tTrails found: {characteristics_found}")
            print(f"\tCurrent Probability: {math.log(diff_prob, 2)}")
            print(f"\tTime: {round(time.time() - start_time, 2)}s")
        parameters["sweight"] += 1

    return diff_prob


def findBestConstants(cipher: AbstractCipher, parameters: Dict[str, Any]) -> List[int]:
    """
    Search for the optimal differential or linear characteristics.
    Works only for SIMON!
    """
    wordsize = parameters["wordsize"]

    constantMinWeights = []
    gamma = parameters["sweight"]
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

            while weight < MAX_WEIGHT:
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
                    print(f"Alpha: {alpha} Beta: {beta} Gamma: {gamma} Weight: {weight}")
                    break
                weight += 1
            constantMinWeights.append(weight)
    print(constantMinWeights)
    return constantMinWeights

def findMinWeightCharacteristic(cipher: AbstractCipher, parameters: Dict[str, Any]) -> int:
    """
    Find a characteristic of minimal weight for the cipher
    parameters = [rounds, wordsize, sweight, isIterative, fixedVariables]
    """

    print(f"Starting search for characteristic with minimal weight\n"
          f"{cipher.name} - Rounds: {parameters['rounds']} Wordsize: {parameters['wordsize']}")
    print("---")

    start_time = time.time()

    while not reachedTimelimit(start_time, parameters["timelimit"]) and \
        parameters["sweight"] < parameters["endweight"]:

        print(f"Weight: {parameters['sweight']} Time: {round(time.time() - start_time, 2)}s")

        # Construct problem instance for given parameters
        stp_file = f"tmp/{cipher.name}{parameters['wordsize']}.stp"
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
            current_time = round(time.time() - start_time, 2)
            print("---")
            print(f"Characteristic for {cipher.name} - Rounds {parameters['rounds']} - "
                   f"Wordsize {parameters['wordsize']} - Weight {parameters['sweight']} - "
                   f"Time {current_time}s")
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
                print(f"Wrote .dot to {parameters['dot']}")
                
            if parameters["latex"]:
                with open(parameters["latex"], "w") as tex_file:
                    tex_file.write(characteristic.getTexString())
                print(f"Wrote .tex to {parameters['latex']}")                
            break
        parameters["sweight"] += 1
    return parameters["sweight"]


def findAllCharacteristics(cipher: AbstractCipher, parameters: Dict[str, Any]) -> None:
    """
    Outputs all characteristics of a specific weight by excluding
    solutions iteratively.
    """
    rnd_string_tmp = f"{random.randrange(16**30):030x}"
    start_time = time.time()
    total_num_characteristics = 0

    while not reachedTimelimit(start_time, parameters["timelimit"]) and \
          parameters["sweight"] != parameters["endweight"]:
        stp_file = f"tmp/{cipher.name}{rnd_string_tmp}.stp"

        # Start STP TODO: add boolector support
        cipher.createSTP(stp_file, parameters)

        result = ""
        if parameters["boolector"]:
            result = solveBoolector(stp_file)
        elif parameters["bitwuzla"]:
            result = solveBitwuzla(stp_file)
        else:
            result = solveSTP(stp_file)

        # Check for solution
        if foundSolution(result):
            print(f"Characteristic for {cipher.name} - Rounds {parameters['rounds']} - "
                   f"Wordsize {parameters['wordsize']}- Weight {parameters['sweight']}")

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
            parameters["blockedCharacteristics"].append(characteristic)
        else:
            print(f"Found {total_num_characteristics} characteristics with weight {parameters['sweight']}")
            parameters["sweight"] += 1
            total_num_characteristics = 0
            continue

        total_num_characteristics += 1

    if parameters["dot"]:
        with open(parameters["dot"], "w") as dot_file:
            dot_file.write("strict digraph graphname {")
            #dot_file.write("graph [ splines = false ]")
            dot_graph = ""
            for characteristic in parameters["blockedCharacteristics"]:
                dot_graph += characteristic.getDOTString()
            dot_file.write(dot_graph)
            dot_file.write("}")
        print(f"Wrote .dot to {parameters['dot']}")
        
    return

def searchCharacteristics(cipher: AbstractCipher, parameters: Dict[str, Any]) -> None:
    """
    Searches for differential characteristics of minimal weight
    for an increasing number of rounds.
    """
    while True:
        print(f"Number of rounds: {parameters['rounds']}")
        parameters["sweight"] = findMinWeightCharacteristic(cipher, parameters)
        print("Rounds:")
        parameters["rounds"] = parameters["rounds"] + 1
    return

def reachedTimelimit(start_time: float, timelimit: int) -> bool:
    """
    Return True if the timelimit was reached.
    """
    if round(time.time() - start_time) >= timelimit and timelimit != -1:
        print(f"Reached the time limit of {timelimit} seconds")
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
    subprocess.check_output([PATH_STP, "--exit-after-CNF", "--output-CNF",
                             stp_file, "--CVC", "--disable-simplifications"])

    # Find the number of solutions with the SAT solver
    sat_params = [PATH_CRYPTOMINISAT, "--maxsol", str(MAX_CHARACTERISTICS),
                  "--verb", "0", "-s", "0", "output_0.cnf"]

    sat_process = subprocess.Popen(sat_params, stderr=subprocess.PIPE,
                                   stdout=subprocess.PIPE)

    return sat_process

def solveSTP(stp_file: str) -> str:
    """
    Returns the solution for the given SMT problem using STP.
    """
    stp_parameters = [PATH_STP, stp_file, "--CVC"]
    result = subprocess.check_output(stp_parameters)

    return result.decode("utf-8")

def solveBoolector(stp_file: str) -> str:
    """
    Returns the solution for the given SMT problem using boolector.
    """
    # Create input file with help of STP
    stp_parameters = [PATH_STP, "--print-back-SMTLIB2", stp_file, "--CVC"]
    input_file = subprocess.check_output(stp_parameters)

    boolector_parameters = [PATH_BOOLECTOR, "-x", "-m"]
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
    input_file = subprocess.check_output(stp_parameters)

    # Bitwuzla requires (check-sat) and (get-model)
    if b"(check-sat)" not in input_file:
        input_file += b"\n(check-sat)\n"
    if b"(get-model)" not in input_file:
        input_file += b"\n(get-model)\n"

    bitwuzla_parameters = [PATH_BITWUZLA, "-m", "--bv-output-format", "16"]
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
