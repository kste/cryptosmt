'''
Created on Mar 28, 2014

@author: stefan
'''

from parser.stpCommands import *
from cipher import AbstractCipher

import random

class ChasKeyMacHalf(AbstractCipher):

    msgblocks = 1

    def __init__(self, msgblocks):
        self.msgblocks = msgblocks
        return
 
    def getName(self):
        return "chaskeyhalf"
    
    def getFormatString(self):
        return ['v0', 'v1', 'v2', 'v3', 'w0', 'w1', 'w2', 'w3', 'weight']

    def createSTP(self, filename, cipherParameters):
        """
        Creates an STP file to find a characteristic for ChasKey with the given parameters.
        """        
        wordsize = cipherParameters[0]
        rounds = cipherParameters[1]
        weight = cipherParameters[2]
        isIterative = cipherParameters[3]
        varsFixed = cipherParameters[4]
        blockedCharacteristics = cipherParameters[5]

        msgblocks = self.msgblocks
        
        with open(filename, 'w') as file:
            file.write("% Input File for STP\n% ChasKeyMac w={} rounds={}\n\n\n".format(wordsize, rounds))
               
            # Setup variable
            # state = v0, v1, v2, v3
            # intermediate values = a0, a1, a2, a3
            v0 = ["v0{}".format(i) for i in range((rounds + 1) * msgblocks)]
            v1 = ["v1{}".format(i) for i in range((rounds + 1) * msgblocks)]
            v2 = ["v2{}".format(i) for i in range((rounds + 1) * msgblocks)]
            v3 = ["v3{}".format(i) for i in range((rounds + 1) * msgblocks)]
            
            # w = weight of each modular addition
            w0 = ["w0{}".format(i) for i in range(rounds* msgblocks)]
            w1 = ["w1{}".format(i) for i in range(rounds* msgblocks)]
            
            StpCommands().setupVariables(file, v0, wordsize)
            StpCommands().setupVariables(file, v1, wordsize)
            StpCommands().setupVariables(file, v2, wordsize)
            StpCommands().setupVariables(file, v3, wordsize)
            StpCommands().setupVariables(file, w0, wordsize)
            StpCommands().setupVariables(file, w1, wordsize)
            
            StpCommands().setupWeightComputation(file, weight, w0 + w1, wordsize, 1)
            
            for i in range(rounds):
                self.setupChasKeyRound(file, i, v0[i], v1[i], v2[i], v3[i],
                                             v0[i + 1], v1[i + 1], v2[i + 1], v3[i + 1],
                                             w0[i], w1[i], wordsize)
            
            # Message Collision        
            StpCommands().assertNonZero(file, v0 + v1 + v2 + v3, wordsize)
            #zeroString = "0hex" + "0"*(wordsize / 4)
            # StpCommands().assertVariableValue(file, v0[rounds], zeroString)
            # StpCommands().assertVariableValue(file, v1[rounds], zeroString)
            # StpCommands().assertVariableValue(file, v2[rounds], zeroString)
            # StpCommands().assertVariableValue(file, v3[rounds], zeroString)

                      
            # Iterative characteristics only
            # Input difference = Output difference               
            if(isIterative):
                StpCommands().assertVariableValue(file, v0[0], v0[rounds])
                StpCommands().assertVariableValue(file, v1[0], v1[rounds])
                StpCommands().assertVariableValue(file, v2[0], v2[rounds])
                StpCommands().assertVariableValue(file, v3[0], v3[rounds])

            if(varsFixed):
                for key, value in varsFixed.iteritems():
                    StpCommands().assertVariableValue(file, key, value)
                    
            if(blockedCharacteristics):
                for char in blockedCharacteristics:
                    StpCommands().blockCharacteristic(file, char, wordsize)
            
            StpCommands().setupQuery(file)

        return

    def setupChasKeyRound(self, file, round, v0in, v1in, v2in, v3in,
                                        v0out, v1out, v2out, v3out,
                                        w0, w1, wordsize):

        file.write(self.getStringForChasKeyRound(round, v0in, v1in, v2in, v3in,
                                        v0out, v1out, v2out, v3out,
                                        w0, w1, wordsize))
        return


    
    def constructParametersList(self, rounds, wordsize, weight):
        """
        TODO:
        """
        return [wordsize, rounds, weight]
    
    def getStringForChasKeyRound(self, round, v0_in, v1_in, v2_in, v3_in,
                                  v0_out, v1_out, v2_out, v3_out, 
                                  w0, w1, wordsize):
        """
        Returns a string representing ChasKeyRound in STP.
        

        a0 = (v1 + v0) <<< 32
        a1 = (v1 + v0) ^ (v1 <<< 13)
        a2 = (v2 + v3)
        a3 = (v2 + v3) ^ (v3 <<< 16)
        """
        command = ""

        if (round % 2) == 0:
            rotOne = 5
            rotTwo = 8
        else:
            rotOne = 7
            rotTwo = 13
        
        #Assert intermediate values

        #Rotate right to get correct output value

        #v0_out
        command += "ASSERT("
        command += StpCommands().getStringAdd(v2_in, v3_in, v0_out, wordsize)
        command += ");\n" 

        #v1_out
        command += "ASSERT({} = BVXOR({}, {}));\n".format(v1_out, 
            StpCommands().getStringLeftRotate(v1_in, rotOne, wordsize), 
            StpCommands().getStringRightRotate(v2_out, 16, wordsize))


        #v2_out
        command += "ASSERT("
        command += StpCommands().getStringAdd(v1_in, 
                                              v0_in, 
                                              StpCommands().getStringRightRotate(v2_out, 16, wordsize), wordsize)
        command += ");\n"


        #v3_out
        command += "ASSERT({} = BVXOR({}, {}));\n".format(v3_out, 
                    StpCommands().getStringLeftRotate(v3_in, rotTwo, wordsize), 
                    v0_out)
                                                                        
        #Compute Weights for modular addition
        # Lipmaa and Moriai
        
        command += "ASSERT({0} = ~".format(w0)
        command += StpCommands().getStringEq(v1_in, 
                                            v0_in,
                                            StpCommands().getStringRightRotate(v2_out, 16, wordsize), wordsize)
        command += ");\n"

        command += "ASSERT({0} = ~".format(w1)
        command += StpCommands().getStringEq(v2_in, v3_in, v0_out, wordsize)
        command += ");\n"

                
        return command

    
    