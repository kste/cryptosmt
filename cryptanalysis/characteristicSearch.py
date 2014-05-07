'''
Created on Apr 3, 2014

@author: stefan
'''

from ciphers import simon, speck
from parser import parseSTPoutput

import subprocess
import random
    
class characteristicSearch:
    '''
    classdocs
    '''

    stpParser = None
    pathToSTP = ""

    def __init__(self, stp):
        '''
        Constructor
        '''
        self.pathToSTP = stp
        self.stpParser = parseSTPoutput.parseSTPoutput()
                          
    def findMinWeightCharacteristic(self, cipher, parameters):
        """
        Find a characteristic of minimal weight for the cipher
        parameters = [rounds, wordsize, sweight, isIterative, fixedVariables]
        """
        print "Starting search for {} - Rounds: {} Wordsize: {}".format(cipher.getName(), parameters["rounds"], parameters["wordsize"])
        weight = parameters["sweight"]
        fixedVariables = parameters["fixedVariables"]
        
        while(True):
            print "Weight: {}".format(weight)
            cipherParameters = cipher.constructParametersList(parameters["rounds"], parameters["wordsize"], weight)
            cipherParameters.append(parameters["iterative"])
            cipherParameters.append(fixedVariables)
            
            cipher.createSTP("tmp/{}.stp".format(cipher.getName()), cipherParameters)
            outputOfProcess = subprocess.check_output([self.pathToSTP, "--cryptominisat", "tmp/{}.stp".format(cipher.getName())])
            
            if("Invalid" in outputOfProcess):
                print "Characteristic for {} - Rounds {} - Wordsize {}".format(cipher.getName(), parameters["rounds"], parameters["wordsize"])
                self.stpParser.printSTPOutputAsCharacteristic(outputOfProcess, ['x', 'y', 'w'], parameters["rounds"])
                break
            weight += 1
        return weight
            
                
    def searchCharacteristics(self, cipher, parameters):
        """
        Searches for differential characteristics of minimal weight
        for an increasing number of rounds.
        """
        while(True):
            print "Number of rounds: {}".format(rounds)
            sweight = self.findMinWeightCharacteristic(cipher, parameters)
            parameters["rounds"] = parameters["rounds"] + 1
            