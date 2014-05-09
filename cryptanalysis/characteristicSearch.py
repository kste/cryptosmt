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
                print "Characteristic for {} - Rounds {} - Wordsize {}- Weight {}".format(cipher.getName(), 
                                                                          parameters["rounds"], 
                                                                          parameters["wordsize"],
                                                                          weight)
                self.stpParser.printSTPOutputAsCharacteristic(outputOfProcess, ['x', 'y', 'w'], parameters["rounds"])
                break
            weight += 1
        return weight
    
    def findAllCharacteristics(self, cipher, parameters):
        """
        Outputs all characteristics of a specific weight by excluding
        solutions iteratively
        """
        randomStringForTMPFile = '%030x' % random.randrange(16**30)
        weight = parameters["sweight"]
        totalNumberOfCharacteristics = 0
        foundCharacteristics = []
        
        while(True):                            
            cipherParameters = cipher.constructParametersList(parameters["rounds"], parameters["wordsize"], weight)
            cipherParameters.append(parameters["iterative"])
            cipherParameters.append(parameters["fixedVariables"])
            cipherParameters.append(foundCharacteristics)
            
            # Start STP
            cipher.createSTP("tmp/{}{}.stp".format(cipher.getName(), randomStringForTMPFile), cipherParameters)
            outputOfProcess = subprocess.check_output([self.pathToSTP, "--cryptominisat", 
                                         "tmp/{}{}.stp".format(cipher.getName(), randomStringForTMPFile)])
            
            # Check for solution
            if("Invalid" in outputOfProcess):
                print "Characteristic for {} - Rounds {} - Wordsize {}- Weight {}".format(cipher.getName(), 
                                                                                          parameters["rounds"], 
                                                                                          parameters["wordsize"],
                                                                                          weight)
                self.stpParser.printSTPOutputAsCharacteristic(outputOfProcess, 
                                                              ['x', 'y', 'w'], 
                                                              parameters["rounds"])
                foundCharacteristics.append(self.stpParser.getCharacteristicFromSTPOutput(outputOfProcess, 
                                                                                          ['x', 'y', 'w'], 
                                                                                          parameters["rounds"]))
            else:
                print "Found {} characteristics\n".format(totalNumberOfCharacteristics)
                break
                
            totalNumberOfCharacteristics += 1
            
                
    def searchCharacteristics(self, cipher, parameters):
        """
        Searches for differential characteristics of minimal weight
        for an increasing number of rounds.
        """
        while(True):
            print "Number of rounds: {}".format(rounds)
            sweight = self.findMinWeightCharacteristic(cipher, parameters)
            parameters["rounds"] = parameters["rounds"] + 1
            