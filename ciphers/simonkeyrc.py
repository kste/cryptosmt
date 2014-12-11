'''
Created on Mar 28, 2014

@author: stefan
'''

from parser import stpcommands
from cipher import AbstractCipher

import random

class SimonKeyRcCipher(AbstractCipher):
 
    def getName(self):
        return "simonkeyrc"

    def getFormatString(self):
        return ['x0r', 'y0r', 'x1r', 'y1r', 'x2r', 'y2r', 'x3r', 'y3r', 'deltax', 'deltay', 'key']
    
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
        
        numMessage = 2

        with open(filename, 'w') as file:
            file.write("% Input File for STP\n% Simon w={} alpha={} beta={} gamma={} rounds={}\n\n\n".format(wordsize, rotAlpha, rotBeta, rotGamma, rounds))
            

            # Setup key
            key = ["key{}".format(i) for i in range(rounds + 1)]
            tmpkey = ["tmpkey{}".format(i) for i in range(rounds + 1)]

            StpCommands().setupVariables(file, key, wordsize)
            StpCommands().setupVariables(file, tmpkey, wordsize)
               
            #TODO Key schedule
            self.setupKeySchedule(file, key, tmpkey, rounds, wordsize)

            # Setup variables
            # x = left, y = right
            for msg in range(numMessage):
                x = ["x{}r{}".format(msg, i) for i in range(rounds + 1)]
                y = ["y{}r{}".format(msg, i) for i in range(rounds + 1)]
                and_out = ["andout{}r{}".format(msg, i) for i in range(rounds + 1)]
                StpCommands().setupVariables(file, x, wordsize)
                StpCommands().setupVariables(file, y, wordsize)
                StpCommands().setupVariables(file, and_out, wordsize)

                #Setup Rounds
                for i in range(rounds):
                    self.setupSimonRound(file, x[i], y[i], x[i+1], y[i+1], and_out[i], key[i], wordsize)
            
            
            #Differences between x0 and x1
            if(numMessage > 1):
                delta_x = ["deltax{}".format(i) for i in range(rounds + 1)]
                delta_y = ["deltay{}".format(i) for i in range(rounds + 1)]
                StpCommands().setupVariables(file, delta_x, wordsize)
                StpCommands().setupVariables(file, delta_y, wordsize)
                for i in range(rounds + 1):
                    file.write("ASSERT({} = BVXOR({}, {}));\n".format(delta_x[i], "x0r{}".format(i), "x1r{}".format(i)))
                    file.write("ASSERT({} = BVXOR({}, {}));\n".format(delta_y[i], "y0r{}".format(i), "y1r{}".format(i)))

            
            #Last round fix
                       
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
        
    def setupSimonRound(self, file, x0_in, y0_in,  x0_out, y0_out, and_out0, key, wordsize):
        file.write(self.getStringForSimonRound(x0_in, y0_in,  x0_out, y0_out, and_out0, key, wordsize) + '\n')
        return
    
    def getStringForSimonRound(self, x0_in, y0_in,  x0_out, y0_out, and_out0, key, wordsize):
        """
        Returns a string representing one round of Simon in STP.
        
        y[i+1] = x[i]
        x[i+1] = (x[i] <<< 1) & (x[i] <<< 8) ^ y[i] ^ (x[i] << 2) 
        """
        command = ""
        
        #Assert(y_out = x_in)
        command += "ASSERT({} = {});\n".format(y0_out, x0_in)
        
        #Assert AND Output
        command += "ASSERT({} = {} & {});\n".format(and_out0, 
                                                  StpCommands().getStringLeftRotate(x0_in, 1, wordsize),
                                                  StpCommands().getStringLeftRotate(x0_in, 8, wordsize))
        #Assert x_out
        command += "ASSERT({} = BVXOR({}, BVXOR({}, BVXOR({}, {}))));\n".format(x0_out, y0_in, and_out0, key, 
                                                    StpCommands().getStringLeftRotate(x0_in, 2, wordsize))
                
        return command

    
    