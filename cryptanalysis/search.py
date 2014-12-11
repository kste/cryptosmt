'''
Created on Apr 3, 2014

@author: stefan
'''

from parser import parsesolveroutput
from config import (PATH_STP, PATH_BOOLECTOR, PATH_CRYPTOMINISAT, MAX_WEIGHT,
                    MAX_CHARACTERISTICS)

import subprocess
import random
import math


def computeProbabilityOfDifferentials(cipher, parameters):
    """
    Computes the probability of the differential by iteratively
    summing up all characteristics of a specific weight using
    a SAT solver.
    """
    rnd_string_tmp = '%030x' % random.randrange(16**30)
    weight = parameters["sweight"]
    diff_prob = 0
    characteristics_found = 0

    while weight < MAX_WEIGHT:
        cipher_parameters = cipher.getParamList(parameters["rounds"],
                                                parameters["wordsize"],
                                                weight)
        cipher_parameters.append(parameters["iterative"])
        cipher_parameters.append(parameters.get("fixedVariables"))
        cipher_parameters.append(parameters.get("blockedCharacteristics"))

        stp_file = "tmp/{}{}.stp".format(cipher.getName(), rnd_string_tmp)
        # Start STP
        cipher.createSTP(stp_file, cipher_parameters)
        subprocess.check_output([PATH_STP, "--exit-after-CNF",
                                 "--output-CNF", stp_file])

        # Find the number of solutions with the SAT solver
        print "Checking for number of solutions of weight " + str(weight)
        sat_params = [PATH_CRYPTOMINISAT, "--maxsol",
                      str(MAX_CHARACTERISTICS), "--verb", "0",
                      "-s", "0", "output_0.cnf"]

        log_file = open("tmp/satlog.tmp", "w")
        sat_process = subprocess.Popen(sat_params, stdout=log_file)
        sat_process.wait()

        with open("tmp/satlog.tmp", "r") as sat_output:
            solutions = 0
            for line in sat_output:
                if "s SATISFIABLE" in line:
                    solutions += 1
            # STP seems to produce wrong CNF which leads
            # to double the solutions.
            solutions /= 2

        # Print result
        diff_prob += math.pow(2, -weight) * solutions
        characteristics_found += solutions
        if diff_prob > 0.0:
            print "\tSolutions: {}".format(solutions)
            print "\tCharacteristics Found: {}".format(characteristics_found)
            print "\tCurrent Probability: " + str(math.log(diff_prob, 2))
        weight += 1


def findMinWeightCharacteristic(cipher, parameters):
    """
    Find a characteristic of minimal weight for the cipher
    parameters = [rounds, wordsize, sweight, isIterative, fixedVariables]
    """

    print("Starting search for characteristic with minimal weight\n"
          "{} - Rounds: {} Wordsize: {}".format(cipher.getName(),
                                                parameters["rounds"],
                                                parameters["wordsize"]))
    print "---"

    weight = parameters["sweight"]

    while weight < MAX_WEIGHT:
        print "Weight: {}".format(weight)
        cipher_params = cipher.getParamList(parameters["rounds"],
                                            parameters["wordsize"],
                                            weight)
        cipher_params.append(parameters["iterative"])
        cipher_params.append(parameters.get("fixedVariables"))
        cipher_params.append(parameters.get("blockedCharacteristics"))

        # Construct problem instance for given parameters
        stp_file = "tmp/{}.stp".format(cipher.getName())
        cipher.createSTP(stp_file, cipher_params)

        result = ""
        if parameters["boolector"]:
            #Use STP to create SMTLIB-2
            input_file = subprocess.check_output([PATH_STP,
                                                 "--print-back-SMTLIB2",
                                                 stp_file])

            #Start Boolector
            opened_process = subprocess.Popen([PATH_BOOLECTOR, "-x", "-m"],
                                              stdout=subprocess.PIPE,
                                              stdin=subprocess.PIPE)
            result = opened_process.communicate(input=input_file)[0]
        else:
            result = subprocess.check_output([PATH_STP, stp_file])

        # Check if a characteristic was found
        if "Valid" not in result and "unsat" not in result:
            print("Characteristic for {} - Rounds {} - Wordsize {}- "
                  "Weight {}".format(cipher.getName(), parameters["rounds"],
                                     parameters["wordsize"], weight))
            characteristic = ""
            if parameters["boolector"]:
                characteristic = parsesolveroutput.getCharBoolectorOutput(
                    result, cipher.getFormatString(), parameters["rounds"])
            else:
                characteristic = parsesolveroutput.getCharSTPOutput(
                    result, cipher.getFormatString(), parameters["rounds"])
            characteristic.printText()
            break
        weight += 1
    return weight


def findAllCharacteristics(cipher, parameters):
    """
    Outputs all characteristics of a specific weight by excluding
    solutions iteratively
    """
    rnd_string_tmp = '%030x' % random.randrange(16**30)
    weight = parameters["sweight"]
    total_num_characteristics = 0
    characteristics_found = []

    while True:
        cipher_params = cipher.getParamList(parameters["rounds"],
                                            parameters["wordsize"],
                                            weight)
        cipher_params.append(parameters["iterative"])
        cipher_params.append(parameters["fixedVariables"])
        cipher_params.append(characteristics_found)

        stp_file = "tmp/{}{}.stp".format(cipher.getName(), rnd_string_tmp)

        # Start STP TODO: add boolector support
        cipher.createSTP(stp_file, cipher_params)
        process_output = subprocess.check_output([PATH_STP,
                                                  "--cryptominisat4",
                                                  stp_file])

        # Check for solution
        if "Invalid" in process_output:
            print("Characteristic for {} - Rounds {} - Wordsize {}- "
                  "Weight {}".format(cipher.getName(), parameters["rounds"],
                                     parameters["wordsize"], weight))

            characteristic = parsesolveroutput.getCharSTPOutput(
                process_output, cipher.getFormatString(),
                parameters["rounds"])

            characteristic.printText()
            characteristics_found.append(characteristic)
        else:
            print "Found {} characteristics with weight {}\n".format(
                total_num_characteristics, weight)
            break

        total_num_characteristics += 1


def searchCharacteristics(cipher, parameters):
    """
    Searches for differential characteristics of minimal weight
    for an increasing number of rounds.
    """
    while True:
        print "Number of rounds: {}".format(parameters["rounds"])
        findMinWeightCharacteristic(cipher, parameters)
        print "Rounds:"
        parameters["rounds"] = parameters["rounds"] + 1
