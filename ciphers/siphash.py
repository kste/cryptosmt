'''
Created on Mar 28, 2014

@author: stefan
'''

from parser.stpCommands import *
from cipher import AbstractCipher

import random

class SipHashCipher(AbstractCipher):

    msgblocks = 1

    def __init__(self, msgblocks):
        self.msgblocks = msgblocks
        return
 
    def getName(self):
        return "siphash"
    
    def getFormatString(self):
        return ['m', 'v0', 'v1', 'v2', 'v3', 'a0', 'a1', 'a2', 'a3', 'w0', 'w1', 'w2', 'w3', 'weight']

    def createSTP(self, filename, cipherParameters):
        """
        Creates an STP file to find a characteristic for SipHash with the given parameters.
        """        
        wordsize = cipherParameters[0]
        rounds = cipherParameters[1]
        weight = cipherParameters[2]
        isIterative = cipherParameters[3]
        varsFixed = cipherParameters[4]
        blockedCharacteristics = cipherParameters[5]

        msgblocks = self.msgblocks
        
        with open(filename, 'w') as file:
            file.write("% Input File for STP\n% Siphash w={} rounds={}\n\n\n".format(wordsize, rounds))
               
            # Setup variable
            # state = v0, v1, v2, v3
            # intermediate values = a0, a1, a2, a3
            v0 = ["v0{}".format(i) for i in range((rounds + 1) * msgblocks)]
            v1 = ["v1{}".format(i) for i in range((rounds + 1) * msgblocks)]
            v2 = ["v2{}".format(i) for i in range((rounds + 1) * msgblocks)]
            v3 = ["v3{}".format(i) for i in range((rounds + 1) * msgblocks)]

            a0 = ["a0{}".format(i) for i in range((rounds + 1) * msgblocks)]
            a1 = ["a1{}".format(i) for i in range((rounds + 1) * msgblocks)]
            a2 = ["a2{}".format(i) for i in range((rounds + 1) * msgblocks)]
            a3 = ["a3{}".format(i) for i in range((rounds + 1) * msgblocks)]

            m = ["m{}".format(i) for i in range(msgblocks)]
            
            # w = weight of each modular addition
            w0 = ["w0{}".format(i) for i in range(rounds* msgblocks)]
            w1 = ["w1{}".format(i) for i in range(rounds* msgblocks)]
            w2 = ["w2{}".format(i) for i in range(rounds* msgblocks)]
            w3 = ["w3{}".format(i) for i in range(rounds* msgblocks)]
            
            StpCommands().setupVariables(file, v0, wordsize)
            StpCommands().setupVariables(file, v1, wordsize)
            StpCommands().setupVariables(file, v2, wordsize)
            StpCommands().setupVariables(file, v3, wordsize)
            StpCommands().setupVariables(file, a0, wordsize)
            StpCommands().setupVariables(file, a1, wordsize)
            StpCommands().setupVariables(file, a2, wordsize)
            StpCommands().setupVariables(file, a3, wordsize)            
            StpCommands().setupVariables(file, w0, wordsize)
            StpCommands().setupVariables(file, w1, wordsize)
            StpCommands().setupVariables(file, w2, wordsize)
            StpCommands().setupVariables(file, w3, wordsize)
            StpCommands().setupVariables(file, m, wordsize)
            
            StpCommands().setupWeightComputation(file, weight, w0 + w1 + w2 + w3, wordsize, 1)
            
            for block in range(self.msgblocks):
                self.setupSipBlock(file, block, rounds, m, v0, v1, v2, v3,
                                                a0, a1, a2, a3,
                                                w0, w1, w2, w3, wordsize)
            


            # # # Internal Collision
            # zeroString = "0hex" + "0"*(wordsize / 4)
            # StpCommands().assertVariableValue(file, v0[rounds], zeroString)
            # StpCommands().assertVariableValue(file, v1[rounds], zeroString)
            # StpCommands().assertVariableValue(file, v2[rounds], zeroString)
            # StpCommands().assertVariableValue(file, v3[rounds], zeroString)
            # StpCommands().assertVariableValue(file, v0[0], zeroString)
            # StpCommands().assertVariableValue(file, v1[0], zeroString)
            # StpCommands().assertVariableValue(file, v2[0], zeroString)         
            # StpCommands().assertVariableValue(file, v3[0], zeroString)
            # StpCommands().assertNonZero(file, m, wordsize)

            # file.write(self.getStringForCollision(v0[rounds], v1[rounds], v2[rounds], v3[rounds], wordsize))

            # #  # # Internal Collision 1 block only!
            # zeroString = "0hex" + "0"*(wordsize / 4)
            # StpCommands().assertVariableValue(file, v0[rounds], zeroString)
            # #StpCommands().assertVariableValue(file, v1[rounds], zeroString)
            # StpCommands().assertVariableValue(file, v2[rounds], zeroString)
            # StpCommands().assertVariableValue(file, v3[rounds], zeroString)
            # StpCommands().assertVariableValue(file, v0[0], zeroString)
            # StpCommands().assertVariableValue(file, v1[0], zeroString)
            # StpCommands().assertVariableValue(file, v2[0], zeroString)         
            # StpCommands().assertVariableValue(file, v3[0], v1[rounds])
            # StpCommands().assertVariableValue(file, m[0], zeroString)
            # StpCommands().assertVariableValue(file, m[1], zeroString)
            # StpCommands().assertNonZero(file, [v3[0]], wordsize)
            #file.write(self.getStringForCollision(v0[rounds], v1[rounds], v2[rounds], v3[rounds], wordsize))



            # # Key Collision
            # StpCommands().assertNonZero(file, [v0[0], v1[0]], wordsize)
            # StpCommands().assertVariableValue(file, v0[0], v3[0])
            # StpCommands().assertVariableValue(file, v1[0], v2[0])


            # file.write(self.getStringForCollision(v0[rounds], v1[rounds], v2[rounds], v3[rounds], wordsize))


            # Message Collision        
            StpCommands().assertNonZero(file, m, wordsize)
            zeroString = "0hex" + "0"*(wordsize / 4)
            StpCommands().assertVariableValue(file, v0[0], zeroString)
            StpCommands().assertVariableValue(file, v1[0], zeroString)
            StpCommands().assertVariableValue(file, v2[0], zeroString)
            StpCommands().assertVariableValue(file, v3[0], zeroString)

            #Assert collision
            file.write(self.getStringForCollision(v0[rounds*msgblocks], v1[rounds*msgblocks], v2[rounds*msgblocks], v3[rounds*msgblocks], wordsize))

            # # Distinguisher
            # for i in m:
            #     zeroString = "0hex" + "0"*(wordsize / 4)
            #     StpCommands().assertVariableValue(file, i, zeroString)

            # StpCommands().assertNonZero(file, v0 + v1 + v2 + v3, wordsize)

            
            # Iterative characteristics only
            # Input difference = Output difference               
            if(varsFixed):
                for key, value in varsFixed.iteritems():
                    StpCommands().assertVariableValue(file, key, value)
                    
            if(blockedCharacteristics):
                for char in blockedCharacteristics:
                    StpCommands().blockCharacteristic(file, char, wordsize)
            
            StpCommands().setupQuery(file)

        return

    def setupSipBlock(self, file, block, rounds, m, v0, v1, v2, v3,
                                a0, a1, a2, a3,
                                w0, w1, w2, w3, wordsize):
        if(rounds == 1):
            round = block
            file.write(self.getStringForSipRound(v0[round], v1[round], v2[round], "BVXOR({}, {})".format(m[block], v3[round]),
                           a0[round], a1[round], a2[round], a3[round],
                           v0[round+1], "BVXOR({}, {})".format(m[block], v1[round+1]), v2[round+1], v3[round+1], 
                           w0[round], w1[round], w2[round], w3[round], wordsize))      
            return
        for round in range(rounds*block, rounds*(block+1)):
            if(round == round*block):
                #Add message block
                file.write(self.getStringForSipRound(v0[round], v1[round], v2[round], "BVXOR({}, {})".format(m[block], v3[round]),
                                           a0[round], a1[round], a2[round], a3[round],
                                           v0[round+1], v1[round+1], v2[round+1], v3[round+1], 
                                           w0[round], w1[round], w2[round], w3[round], wordsize))
            elif(round == (round*block + (rounds - 1))):
                #Add message block
                file.write(self.getStringForSipRound(v0[round], v1[round], v2[round], v3[round],
                                           a0[round], a1[round], a2[round], a3[round],
                                           v0[round+1], "BVXOR({}, {})".format(m[block], v1[round+1]), v2[round+1], v3[round+1], 
                                           w0[round], w1[round], w2[round], w3[round], wordsize))
            else:
                file.write(self.getStringForSipRound(v0[round], v1[round], v2[round], v3[round],
                                           a0[round], a1[round], a2[round], a3[round],
                                           v0[round+1], v1[round+1], v2[round+1], v3[round+1], 
                                           w0[round], w1[round], w2[round], w3[round], wordsize))



    def getStringForCollision(self, v0, v1, v2, v3, wordsize):
        #Collision including the XOR of the message
        command = ""
        command += "ASSERT(0hex{} = BVXOR({}, BVXOR({}, BVXOR({}, {}))));\n".format("0"*(wordsize / 4), v0, v1, v2, v3)
        return command        
    
    def constructParametersList(self, rounds, wordsize, weight):
        """
        TODO:
        """
        return [wordsize, rounds, weight]
    
        
    # def setupSipRound(self, file, m, v0_in, v1_in, v2_in, v3_in,
    #                               a0, a1, a2, a3,
    #                               v0_out, v1_out, v2_out, v3_out, 
    #                               w0, w1, w2, w3, wordsize):
    #     file.write(self.getStringForSipRound(m, v0_in, v1_in, v2_in, v3_in,
    #                               a0, a1, a2, a3,
    #                               v0_out, v1_out, v2_out, v3_out, 
    #                               w0, w1, w2, w3, wordsize) + '\n')
    #     return
    
    
    def getStringForSipRound(self, v0_in, v1_in, v2_in, v3_in,
                                  a0, a1, a2, a3,
                                  v0_out, v1_out, v2_out, v3_out, 
                                  w0, w1, w2, w3, wordsize):
        """
        Returns a string representing SipRound in STP.
        

        a0 = (v1 + v0) <<< 32
        a1 = (v1 + v0) ^ (v1 <<< 13)
        a2 = (v2 + v3)
        a3 = (v2 + v3) ^ (v3 <<< 16)

        v0_out = (a0 + a3)
        v1_out = (a2 + a1) ^ (a1 <<< 17)
        v2_out = (a2 + a1) <<< 32
        v3_out = (a0 + a3) ^ (a3 <<< 21)
        """
        command = ""
        
        #Assert intermediate values

        #Rotate right to get correct output value
        #a0
        command += "ASSERT("
        command += StpCommands().getStringAdd(v1_in, 
                                              v0_in, 
                                              StpCommands().getStringRightRotate(a0, 32, wordsize), wordsize)
        command += ");\n"

        #a1
        command += "ASSERT({} = BVXOR({}, {}));\n".format(a1, 
            StpCommands().getStringLeftRotate(v1_in, 13, wordsize), 
            StpCommands().getStringRightRotate(a0, 32, wordsize))

        #a2
        command += "ASSERT("
        command += StpCommands().getStringAdd(v2_in, v3_in, a2, wordsize)
        command += ");\n" 

        #a3
        command += "ASSERT({} = BVXOR({}, {}));\n".format(a3, 
                    StpCommands().getStringLeftRotate(v3_in, 16, wordsize), 
                    a2)

        #v0_out
        command += "ASSERT("
        command += StpCommands().getStringAdd(a0, a3, v0_out, wordsize)
        command += ");\n"        

        #v1_out
        command += "ASSERT({} = BVXOR({}, {}));\n".format(v1_out,
            StpCommands().getStringLeftRotate(a1, 17, wordsize), 
            StpCommands().getStringRightRotate(v2_out, 32, wordsize))        

        #v2_out
        command += "ASSERT("
        command += StpCommands().getStringAdd(a2, 
                                              a1, 
                                              StpCommands().getStringRightRotate(v2_out, 32, wordsize), wordsize)
        command += ");\n" 

        #v3_out
        command += "ASSERT({} = BVXOR({}, {}));\n".format(v3_out, 
                    StpCommands().getStringLeftRotate(a3, 21, wordsize), 
                    v0_out)        






        
                                                                  
        #Compute Weights for modular addition
        # Use Hamming weight
        # command += "ASSERT({} = {} | {} | {});\n".format(w0, v1_in, v0_in, a0)
        # command += "ASSERT({} = {} | {} | {});\n".format(w1, v2_in, "BVXOR({}, {})".format(v3_in, m), a2)
        # command += "ASSERT({} = {} | {} | {});\n".format(w2, a0, a3, v0_out)
        # command += "ASSERT({} = {} | {} | {});\n".format(w3, a2, a1, v2_out)

        # Lipmaa and Moriai
        
        command += "ASSERT({0} = ~".format(w0)
        command += StpCommands().getStringEq(v1_in, 
                                            v0_in,
                                            StpCommands().getStringRightRotate(a0, 32, wordsize), wordsize)
        command += ");\n"

        command += "ASSERT({0} = ~".format(w1)
        command += StpCommands().getStringEq(v2_in, v3_in, a2, wordsize)
        command += ");\n"

        command += "ASSERT({0} = ~".format(w2)
        command += StpCommands().getStringEq(a0, a3, v0_out, wordsize)
        command += ");\n"

        command += "ASSERT({0} = ~".format(w3)
        command += StpCommands().getStringEq(a2, 
                                            a1,
                                            StpCommands().getStringRightRotate(v2_out, 32, wordsize), wordsize)
        command += ");\n"

                
        return command

    
    