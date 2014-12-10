'''
Created on Apr 3, 2014

@author: stefan
'''

from ciphers import simon, speck
from parser import parseSTPoutput, parseBoolectorOutput
from config import *

import subprocess
import random


class CharacteristicSearch(object):
    '''
    This class implements various strategies to find characteristics.
    '''

    boolector_parser = None
    stp_parser = None
    pathToSTP = ""

    #Only search characteristics up to a probability of 2^-c
    MAX_WEIGHT = 1000

    def __init__(self):
        '''
        Constructor
        '''
        self.stp_parser = parseSTPoutput.parseSTPoutput()
        self.boolector_parser = parseBoolectorOutput.parseBoolectorOutput()

    def findMinWeightCharacteristic(self, cipher, parameters):
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
            cipher_params = cipher.constructParametersList(
                parameters["rounds"], parameters["wordsize"], weight)
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
                print("Characteristic for {} - Rounds {} - Wordsize {}-"
                      "Weight {}".format(cipher.getName(), parameters["rounds"],
                                         parameters["wordsize"], weight))

                if parameters["boolector"]:
                    self.boolector_parser.printBoolectorOutputAsCharacteristic(
                        result, cipher.getFormatString(), parameters["rounds"])
                else:
                    self.stp_parser.printSTPOutputAsCharacteristic(
                        result, cipher.getFormatString(), parameters["rounds"])
                #print outputOfProcess
                break
            weight += 1
        return weight

    def findAllCharacteristics(self, cipher, parameters):
        """
        Outputs all characteristics of a specific weight by excluding
        solutions iteratively
        """
        rnd_string_tmp = '%030x' % random.randrange(16**30)
        weight = parameters["sweight"]
        total_num_characteristics = 0
        foundCharacteristics = []

        while weight < MAX_WEIGHT:
            cipher_params = cipher.constructParametersList(parameters["rounds"],
                                                           parameters["wordsize"],
                                                           weight)
            cipher_params.append(parameters["iterative"])
            cipher_params.append(parameters["fixedVariables"])
            cipher_params.append(foundCharacteristics)

            stp_file = "tmp/{}{}.stp".format(cipher.getName(), randomStringForTMPFile)

            # Start STP TODO: add boolector support
            cipher.createSTP(stp_file, cipher_params)
            outputOfProcess = subprocess.check_output([PATH_STP,
                                                      "--cryptominisat4",
                                                      stp_file])

            # Check for solution
            if "Invalid" in outputOfProcess:
                print("Characteristic for {} - Rounds {} - Wordsize {}-"
                      "Weight {}".format(cipher.getName(), parameters["rounds"],
                                         parameters["wordsize"], weight))

                self.stp_parser.printSTPOutputAsCharacteristic(
                    outputOfProcess, cipher.getFormatString(),
                    parameters["rounds"])

                #TODO: self print characteristic
                characteristic = self.stp_parser.getCharacteristicFromSTPOutput(
                    outputOfProcess, cipher.getFormatString(),
                    parameters["rounds"])

                foundCharacteristics.append(characteristic)
            else:
                print "Found {} characteristics\n".format(total_num_characteristics)
                break

            total_num_characteristics += 1

    def searchCharacteristics(self, cipher, parameters):
        """
        Searches for differential characteristics of minimal weight
        for an increasing number of rounds.
        """
        while(True):
            print "Number of rounds: {}".format(rounds)
            weight = self.findMinWeightCharacteristic(cipher, parameters)
            print "Rounds:"
            parameters["rounds"] = parameters["rounds"] + 1
