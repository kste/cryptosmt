'''
Created on Apr 3, 2014

@author: stefan
'''

from ciphers import simon, speck
from parser import parseSTPoutput
from config import *

import subprocess
import random
import math
import time


class differentialSearch:
    '''
    classdocs
    '''

    stpParser = None

    def __init__(self):
        '''
        Constructor
        '''
        self.stpParser = parseSTPoutput.parseSTPoutput()

    def computeProbabilityOfDifferentials(self, cipher, parameters):
        """
        Computes the probability of the differential by iteratively 
        summing up all characteristics of a specific weight using
        a SAT solver.
        """
        randomStringForTMPFile = '%030x' % random.randrange(16**30)
        weight = parameters["sweight"]
        diffProbability = 0
        totalNumberOfCharacteristics = 0
        
        while(True):                            
            cipherParameters = cipher.constructParametersList(parameters["rounds"], parameters["wordsize"], weight)
            cipherParameters.append(parameters["iterative"])
            cipherParameters.append(parameters.get("fixedVariables"))
            cipherParameters.append(parameters.get("blockedCharacteristics"))
            
            # Start STP
            cipher.createSTP("tmp/{}{}.stp".format(cipher.getName(), randomStringForTMPFile), cipherParameters)
            p = subprocess.check_output([self.pathToSTP, "--exit-after-CNF", "--output-CNF", 
                                         "tmp/{}{}.stp".format(cipher.getName(), randomStringForTMPFile)])
            
            # Find the number of solutions with the SAT solver
            print "Checking for number of solutions of weight " + str(weight)
            satParameters = [self.pathToSATSolver, "--maxsol", "10000000", "--verb", "0", "-s", "0", "output_0.cnf"]

            logFile = open("tmp/satlog.tmp", "w")
            satProcess = subprocess.Popen(satParameters, stdout=logFile)
            retCode = satProcess.wait()

            with open("tmp/satlog.tmp", "r") as f:
                solutions = 0
                for line in f:
                    if("s SATISFIABLE" in line):
                        solutions += 1
                solutions /= 2 #STP seems to produce wrong CNF which leads to double the solutions

            # try:
            #     p = subprocess.check_output(satParameters)
            # except subprocess.CalledProcessError, e:
            #     # This always happens as UNSAT will be returned when
            #     # no more solutions exist!
            #     solutions = (e.output.count("SATISFIABLE") - 1) / 2 #STP seems to produce wrong CNF which leads to double the solutions
                
            # Print result
            diffProbability += math.pow(2, -weight) * solutions
            totalNumberOfCharacteristics += solutions
            if(diffProbability > 0):
                print "\tSolutions: {}".format(solutions)
                print "\tCharacteristics Found: {}".format(totalNumberOfCharacteristics)
                print "\tCurrent Probability: " + str(math.log(diffProbability, 2))
            weight += 1
