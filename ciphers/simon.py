'''
Created on Mar 28, 2014

@author: stefan
'''

from parser.stpCommands import *
from cipher import AbstractCipher

import random

class SimonCipher(AbstractCipher):
 
    def getName(self):
        return "simon"
    
    def createSTP(self, filename, cipherParameters):
        """
        Creates an STP file to find a characteristic for Simon with the given parameters.
        """        
        wordsize = cipherParameters[0]
        rotAlpha = cipherParameters[1]
        rotBeta = cipherParameters[2]
        rotGamma = cipherParameters[3]
        rounds = cipherParameters[4]
        weight = cipherParameters[5]
        isIterative = cipherParameters[6]
        varsFixed = cipherParameters[7]
        blockedCharacteristics = cipherParameters[8]
        
        with open(filename, 'w') as file:
            file.write("% Input File for STP\n% Simon w={} alpha={} beta={} gamma={} rounds={}\n\n\n".format(wordsize, rotAlpha, rotBeta, rotGamma, rounds))
               
            # Setup variable
            # x = left, y = right
            x = ["x{}".format(i) for i in range(rounds + 1)]
            y = ["y{}".format(i) for i in range(rounds + 1)]
            and_out = ["andout{}".format(i) for i in range(rounds + 1)]
            
            # w = weight
            w = ["w{}".format(i) for i in range(rounds)]
            
            StpCommands().setupVariables(file, x, wordsize)
            StpCommands().setupVariables(file, y, wordsize)
            StpCommands().setupVariables(file, and_out, wordsize)
            StpCommands().setupVariables(file, w, wordsize)
            
            StpCommands().setupWeightComputation(file, weight, w, wordsize)
               
            for i in range(rounds):
                self.setupSimonRound(file, x[i], y[i], x[i+1], y[i+1], and_out[i], w[i], rotAlpha, rotBeta, rotGamma, wordsize)
        
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
                    
            if(blockedCharacteristics):
                for char in blockedCharacteristics:
                    StpCommands().blockCharacteristic(file, char, wordsize)
            
            StpCommands().setupQuery(file)

        return
    
    def constructParametersList(self, rounds, wordsize, weight):
        """
        TODO:
        """
        return [wordsize, 1, 8, 2, rounds, weight]
    
        
    def setupSimonRound(self, file, x_in, y_in, x_out, y_out, and_out, w, rotAlpha, rotBeta, rotGamma, wordsize):
        file.write(self.getStringForSimonRound(x_in, y_in, x_out, y_out, and_out, w, rotAlpha, rotBeta, rotGamma, wordsize) + '\n')
        return
    
    def getDependentBitsForAND(self, x_in, wordsize):
        "rotate_right(diff, 6) & (~rotate_left(diff, 1)) & rotate_left(diff, 8);"
        command = "({0} & (~{1}) & {2})".format(StpCommands().getStringRightRotate(x_in, 6, wordsize),
                                              StpCommands().getStringLeftRotate(x_in, 1, wordsize),
                                              StpCommands().getStringLeftRotate(x_in, 8, wordsize));
        return command
    
    def getStringForSimonRound(self, x_in, y_in, x_out, y_out, and_out, w, rotAlpha, rotBeta, rotGamma, wordsize):
        """
        Returns a string representing one round of Simon in STP.
        
        y[i+1] = x[i]
        x[i+1] = (x[i] <<< 1) & (x[i] <<< 8) ^ y[i] ^ (x[i] << 2) 
        """
        command = ""
        
        #Assert(y_out = x_in)
        command += "ASSERT({} = {});\n".format(y_out, x_in)
        
        #Assert AND Output
        command += "ASSERT(" + StpCommands().getStringForAndDifferential(StpCommands().getStringLeftRotate(x_in, rotAlpha, wordsize),
                                                            StpCommands().getStringLeftRotate(x_in, rotBeta, wordsize),
                                                            and_out) + " = 0hex{});\n".format("f"*(wordsize / 4))
                  
                  
        #Deal with dependent inputs
        dependentRotated = StpCommands().getStringLeftRotate(self.getDependentBitsForAND(x_in, wordsize),7,wordsize)
        andoutRotatedMasked = StpCommands().getStringRightRotate("({0} & {1})".format(and_out,dependentRotated), 7, wordsize)
        
        command += "ASSERT(BVXOR({0} & {1}, {2}) = 0hex{3});\n".format(and_out, self.getDependentBitsForAND(x_in, wordsize), andoutRotatedMasked, "0"*(wordsize / 4))          
                                                            
        #Assert XORs
        command += "ASSERT(" + x_out + " = "
        command += "BVXOR("
        command += StpCommands().getStringLeftRotate(x_in, rotGamma, wordsize)
        command += ", BVXOR(" + y_in + ", " + and_out + ")"
        command += "));\n"
                                                            
        #More improved :)
        command += "ASSERT({0} = (IF {2} = 0x{4} THEN BVSUB({5},0x{4},0x{6}1) ELSE BVXOR(~{1} & ~{2} & {3}, {2}) ENDIF));".format(w, StpCommands().getStringRightRotate(x_in, 7, wordsize),
                                                                          x_in, StpCommands().getStringRightRotate(x_in, 14, wordsize),
                                                                          "f"*(wordsize / 4), wordsize, "0"*((wordsize / 4)- 1));
        
                                                                  
                
        return command

    
    