'''
Created on Mar 28, 2014

@author: stefan
'''

from parser.stpCommands import *
from cipher import AbstractCipher

import random

class SpeckCipher(AbstractCipher):
    
    def getName(self):
        return "speck"
    
    def createSTP(self, filename, cipherParameters):
        wordsize = cipherParameters[0]
        rotAlpha = cipherParameters[1]
        rotBeta = cipherParameters[2]
        rounds = cipherParameters[3]
        weight = cipherParameters[4]
        isIterative = cipherParameters[5]
        varsFixed = cipherParameters[6]
    
        with open(filename, 'w') as file:
            file.write("% Input File for STP\n% Speck w={} alpha={} beta={} rounds={}\n\n\n".format(wordsize, rotAlpha, rotBeta, rounds))
        
            # Setup variable
            # x = left, y = right
            # w = weight
            x = ["x{}".format(i) for i in range(rounds + 1)]
            y = ["y{}".format(i) for i in range(rounds + 1)]
            w = ["w{}".format(i) for i in range(rounds)]
        
        
            StpCommands().setupVariables(file, x, wordsize)
            StpCommands().setupVariables(file, y, wordsize)
            StpCommands().setupVariables(file, w, wordsize)
        
            # Ignore MSB
            StpCommands().setupWeightComputation(file, weight, w, wordsize, 1)
                    
            for i in range(rounds):
                self.setupSpeckRound(file, x[i], y[i], x[i+1], y[i+1], w[i], rotAlpha, rotBeta, wordsize)
            
            # No all zero characteristic
            StpCommands().assertNonZero(file, x + y, wordsize)
            
            # Iterative characteristics only
            # Input difference = Output difference
            if(isIterative):
                StpCommands().assertVariableValue(file, x[0], x[rounds])
                StpCommands().assertVariableValue(file, y[0], y[rounds])
                
            if(varsFixed):
                for key, value in varsFixed.iteritems():
                    StpCommands().assertVariableValue(file, key, value)
            
            StpCommands().setupQuery(file)

        return
    
    def constructParametersList(self, rounds, wordsize, weight):
        """
        TODO:
        """
        if(wordsize == 16):
            return [wordsize, 7, 2, rounds, weight]
        else:
            return [wordsize, 8, 3, rounds, weight]
    
    def setupSpeckRound(self, file, x_in, y_in, x_out, y_out, w, rotAlpha, rotBeta, wordsize):
        file.write(self.getStringForSpeckRound(x_in, y_in, x_out, y_out, w, rotAlpha, rotBeta, wordsize) + '\n')
        return
        
    def getStringForSpeckRound(self, x_in, y_in, x_out, y_out, w, rotAlpha, rotBeta, wordsize):
        command = ""
        
        #Assert(x_in >>> rotAlpha + y_in = x_out)
        command += "ASSERT("
        command += StpCommands().getStringAdd(StpCommands().getStringRightRotate(x_in, rotAlpha, wordsize), y_in, x_out, wordsize)
        command += ");\n"
        
        #Assert(x_out xor (y_in <<< rotBeta) = x_in)
        command += "ASSERT(" + y_out + " = "
        command += "BVXOR(" + x_out + ","
        command += StpCommands().getStringLeftRotate(y_in, rotBeta, wordsize)
        command += "));\n"
        
        #For weight computation
        command += "ASSERT({0} = ~".format(w)
        command += StpCommands().getStringEq(StpCommands().getStringRightRotate(x_in, rotAlpha, wordsize), y_in, x_out, wordsize)
        command += ");" 
        
        return command
    
    