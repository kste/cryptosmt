'''
Created on Mar 28, 2014

@author: stefan
'''

from parser.stpCommands import *
from cipher import AbstractCipher

import random

class SimonKeyRcCipher(AbstractCipher):
 
    def getName(self):
        return "simonkeyrc"

    def getFormatString(self):
        return ['x0', 'y0', 'x1', 'y1', 'deltax', 'deltay', 'key']
    
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
            x0 = ["x0{}".format(i) for i in range(rounds + 1)]
            x1 = ["x1{}".format(i) for i in range(rounds + 1)]
            y0 = ["y0{}".format(i) for i in range(rounds + 1)]
            y1 = ["y1{}".format(i) for i in range(rounds + 1)]
            key = ["key{}".format(i) for i in range(rounds + 1)]
            tmpkey = ["tmpkey{}".format(i) for i in range(rounds + 1)]
            and_out0 = ["andout0{}".format(i) for i in range(rounds + 1)]
            and_out1 = ["andout1{}".format(i) for i in range(rounds + 1)]
            delta_x = ["deltax{}".format(i) for i in range(rounds + 1)]
            delta_y = ["deltay{}".format(i) for i in range(rounds + 1)]
            
            # w = weight
            
            StpCommands().setupVariables(file, x0, wordsize)
            StpCommands().setupVariables(file, x1, wordsize)
            StpCommands().setupVariables(file, y0, wordsize)
            StpCommands().setupVariables(file, y1, wordsize)
            StpCommands().setupVariables(file, key, wordsize)
            StpCommands().setupVariables(file, tmpkey, wordsize)
            StpCommands().setupVariables(file, and_out0, wordsize)
            StpCommands().setupVariables(file, and_out1, wordsize)
            StpCommands().setupVariables(file, delta_x, wordsize)
            StpCommands().setupVariables(file, delta_y, wordsize)
               
            #TODO Key schedule
            self.setupKeySchedule(file, key, tmpkey, rounds, wordsize)

            for i in range(rounds):
                self.setupSimonRound(file, x0[i], x1[i], y0[i], y1[i], 
                                     x0[i+1], x1[i+1], y0[i+1], y1[i+1],
                                     and_out0[i], and_out1[i], key[i], 
                                     delta_x[i], delta_y[i], wordsize)

            #Last round fix
            file.write("ASSERT({} = BVXOR({}, {}));\n".format(delta_x[rounds], x0[rounds], x1[rounds]))
            file.write("ASSERT({} = BVXOR({}, {}));\n".format(delta_y[rounds], y0[rounds], y1[rounds]))
                       
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
    
    def setupKeySchedule(self, file, key, tmpkey, rounds, wordsize):
        command = ""
        if(rounds > 4):
            for i in range(4, rounds):
                tmp = "BVXOR({}, {})".format(StpCommands().getStringRightRotate(key[i-1], 3, wordsize),
                        key[i-3])
                command += "ASSERT({} = BVXOR({}, {}));\n".format(tmpkey[i], tmp, 
                            StpCommands().getStringRightRotate(tmp, 1, wordsize))
                command += "ASSERT({} = BVXOR(~{}, {}));\n".format(key[i], key[i-4], tmpkey[i])
        file.write(command)
        return
        
    def setupSimonRound(self, file, x0_in, x1_in, y0_in, y1_in, 
                        x0_out, x1_out, y0_out, y1_out, and_out0, and_out1, 
                        key, deltax, deltay, wordsize):
        file.write(self.getStringForSimonRound(x0_in, x1_in, y0_in, y1_in, 
                        x0_out, x1_out, y0_out, y1_out, and_out0, and_out1, 
                        key, deltax, deltay, wordsize) + '\n')
        return
    
    def getStringForSimonRound(self, x0_in, x1_in, y0_in, y1_in, 
                        x0_out, x1_out, y0_out, y1_out, and_out0, and_out1, 
                        key, deltax, deltay, wordsize):
        """
        Returns a string representing one round of Simon in STP.
        
        y[i+1] = x[i]
        x[i+1] = (x[i] <<< 1) & (x[i] <<< 8) ^ y[i] ^ (x[i] << 2) 
        """
        command = ""
        
        #Assert difference
        command += "ASSERT({} = BVXOR({}, {}));\n".format(deltax, x0_in, x1_in)
        command += "ASSERT({} = BVXOR({}, {}));\n".format(deltay, y0_in, y1_in)

        #Assert(y_out = x_in)
        command += "ASSERT({} = {});\n".format(y0_out, x0_in)
        command += "ASSERT({} = {});\n".format(y1_out, x1_in)
        
        #Assert AND Output
        command += "ASSERT({} = {} & {});\n".format(and_out0, 
                                                  StpCommands().getStringLeftRotate(x0_in, 1, wordsize),
                                                  StpCommands().getStringLeftRotate(x0_in, 8, wordsize))
        command += "ASSERT({} = {} & {});\n".format(and_out1, 
                                                  StpCommands().getStringLeftRotate(x1_in, 1, wordsize),
                                                  StpCommands().getStringLeftRotate(x1_in, 8, wordsize))

        #Assert x_out
        command += "ASSERT({} = BVXOR({}, BVXOR({}, BVXOR({}, {}))));\n".format(x0_out, y0_in, and_out0, key, 
                                                    StpCommands().getStringLeftRotate(x0_in, 2, wordsize))
        command += "ASSERT({} = BVXOR({}, BVXOR({}, BVXOR({}, {}))));\n".format(x1_out, y1_in, and_out1, key, 
                                                    StpCommands().getStringLeftRotate(x1_in, 2, wordsize))                                                          
                
        return command

    
    