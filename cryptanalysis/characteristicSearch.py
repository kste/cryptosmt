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
        
    def findBestConstants(self, cipher, parameters):
        constants = [[0 for x in xrange(parameters["wordsize"])] for x in xrange(parameters["wordsize"])] 
        
        randomStringForTMPFile = '%030x' % random.randrange(16**30)
        #fix one constant
        for alpha in range(1, parameters["wordsize"]):    
            for beta in range(1, parameters["wordsize"]):
                print "Alpha {} Beta {}".format(alpha, beta)
                weight = 0
                while(True):
                    weight += 1
                    print "Weight: " + str(weight)
                    cipherParameters = cipher.constructParametersList(parameters["rounds"], parameters["wordsize"], weight)
                    #change constants
                    cipherParameters[1] = alpha
                    cipherParameters[2] = beta
                    if(cipher.getName() == "simon"):
                        cipherParameters[3] = 2
                    cipherParameters.append(parameters["iterative"])
                    cipherParameters.append(parameters.get("fixedVariables"))
                    cipherParameters.append(parameters.get("blockedCharacteristics"))
                    
                    cipher.createSTP("tmp/{}{}.stp".format(cipher.getName(), randomStringForTMPFile), cipherParameters)
                    outputOfProcess = subprocess.check_output([self.pathToSTP, "--cryptominisat4", 
                                                               "tmp/{}{}.stp".format(cipher.getName(), randomStringForTMPFile)])
                    if("Invalid" in outputOfProcess):
                        print weight
                        constants[alpha][beta] = weight
                        print constants
                        break
                 
        print constants  
                          
    def findMinWeightCharacteristic(self, cipher, parameters):
        """
        Find a characteristic of minimal weight for the cipher
        parameters = [rounds, wordsize, sweight, isIterative, fixedVariables]
        """
        print "Starting search for {} - Rounds: {} Wordsize: {}".format(cipher.getName(), parameters["rounds"], parameters["wordsize"])
        weight = parameters["sweight"]
        
        while(True):
            print "Weight: {}".format(weight)
            cipherParameters = cipher.constructParametersList(parameters["rounds"], parameters["wordsize"], weight)
            cipherParameters.append(parameters["iterative"])
            cipherParameters.append(parameters.get("fixedVariables"))
            cipherParameters.append(parameters.get("blockedCharacteristics"))
            
            cipher.createSTP("tmp/{}.stp".format(cipher.getName()), cipherParameters)
            outputOfProcess = subprocess.check_output([self.pathToSTP, "tmp/{}.stp".format(cipher.getName())])
            
            if("Invalid" in outputOfProcess):
                print "Characteristic for {} - Rounds {} - Wordsize {}- Weight {}".format(cipher.getName(), 
                                                                          parameters["rounds"], 
                                                                          parameters["wordsize"],
                                                                          weight)
                self.stpParser.printSTPOutputAsCharacteristic(outputOfProcess, cipher.getFormatString(), parameters["rounds"])
                #print outputOfProcess
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
            outputOfProcess = subprocess.check_output([self.pathToSTP, "--cryptominisat4", 
                                         "tmp/{}{}.stp".format(cipher.getName(), randomStringForTMPFile)])
            
            # Check for solution
            if("Invalid" in outputOfProcess):
                print "Characteristic for {} - Rounds {} - Wordsize {}- Weight {}".format(cipher.getName(), 
                                                                                          parameters["rounds"], 
                                                                                          parameters["wordsize"],
                                                                                          weight)
                self.stpParser.printSTPOutputAsCharacteristic(outputOfProcess, 
                                                              cipher.getFormatString(), 
                                                              parameters["rounds"])
                foundCharacteristics.append(self.stpParser.getCharacteristicFromSTPOutput(outputOfProcess, 
                                                                                          cipher.getFormatString(), 
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
            