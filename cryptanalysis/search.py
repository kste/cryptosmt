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
import os

from fractions import gcd


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
    sat_logfile = "tmp/satlog{}.tmp".format(rnd_string_tmp)

    while weight < MAX_WEIGHT:
        if(os.path.isfile(sat_logfile)):
            os.remove(sat_logfile)

        cipher_params = cipher.getParamList(parameters["rounds"],
                                            parameters["wordsize"],
                                            weight)
        cipher_params.append(parameters["iterative"])
        cipher_params.append(parameters.get("fixedVariables"))
        cipher_params.append(parameters.get("blockedCharacteristics"))
        cipher_params.append(parameters.get("nummessages"))

        stp_file = "tmp/{}{}.stp".format(cipher.getName(), rnd_string_tmp)
        # Start STP
        cipher.createSTP(stp_file, cipher_params)
        subprocess.check_output([PATH_STP, "--exit-after-CNF",
                                 "--output-CNF", stp_file])

        # Find the number of solutions with the SAT solver
        print "Checking for number of solutions of weight " + str(weight)
        sat_params = [PATH_CRYPTOMINISAT, "--maxsol",
                      str(MAX_CHARACTERISTICS), "--verb", "0",
                      "-s", "0", "output_0.cnf"]

        log_file = open(sat_logfile, "w")
        sat_process = subprocess.Popen(sat_params, stdout=log_file)
        sat_process.wait()

        with open(sat_logfile, "r") as sat_output:
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


def findBestConstants(cipher, parameters):
    """
    Search for the optimal differential or linear characteristics.
    Works only for SIMON!
    """
    weight = parameters["sweight"]
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
                constantMinWeights.append(constantMinWeights[alpha*wordsize + beta])
                continue
            #Filter gcd(alpha - beta, n) != 1 cases
            if gcd(alpha - beta, wordsize) != 1:
                constantMinWeights.append(1)
                continue

            while weight < MAX_WEIGHT:
                #print "Weight: {}".format(weight)
                cipher_params = cipher.getParamList(parameters["rounds"],
                                                    parameters["wordsize"],
                                                    weight)
                cipher_params[1] = alpha
                cipher_params[2] = beta
                cipher_params[3] = gamma
                cipher_params.append(parameters["iterative"])
                cipher_params.append(parameters.get("fixedVariables"))
                cipher_params.append(parameters.get("blockedCharacteristics"))
                cipher_params.append(parameters.get("nummessages"))

                # Construct problem instance for given parameters
                stp_file = "tmp/{}_{}const.stp".format(cipher.getName(), gamma)
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
                    #print("Characteristic for {} - Rounds {} - Wordsize {}- "
                    #      "Weight {}".format(cipher.getName(), parameters["rounds"],
                    #                         parameters["wordsize"], weight))
                    print "Alpha: {} Beta: {} Gamma: {} Weight: {}".format(alpha, beta, gamma, weight)
                    characteristic = ""
                    if parameters["boolector"]:
                        characteristic = parsesolveroutput.getCharBoolectorOutput(
                            result, cipher.getFormatString(), parameters["rounds"])
                    else:
                        characteristic = parsesolveroutput.getCharSTPOutput(
                            result, cipher.getFormatString(), parameters["rounds"])
                    #characteristic.printText()
                    break
                weight += 1
            constantMinWeights.append(weight)
    print constantMinWeights


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
        cipher_params.append(parameters.get("nummessages"))

        # Construct problem instance for given parameters
        stp_file = "tmp/{}{}.stp".format(cipher.getName(), parameters["wordsize"])
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
        cipher_params.append(parameters.get("nummessages"))

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
        parameters["sweight"] = findMinWeightCharacteristic(cipher, parameters)
        print "Rounds:"
        parameters["rounds"] = parameters["rounds"] + 1
        if(parameters["rounds"] > 16):
            return
