'''
Created on Oct 14, 2014

@author: stefan
'''

from parser.stpCommands import *
from cipher import AbstractCipher

import random

class KeccakCipher(AbstractCipher):
    
    ro = [[0,    36,     3,    41,    18]    ,
          [1,    44,    10,    45,     2]    ,
          [62,    6,    43,    15,    61]    ,
          [28,   55,    25,    21,    56]    ,
          [27,   20,    39,     8,    14]    ]
    
    rc = ["0hex0001", 
          "0hex8082", 
          "0hex808A",
          "0hex8000",
          "0hex808B",
          "0hex0001",
          "0hex8081",
          "0hex8009"
          ]
 
    def getName(self):
        return "Keccak"
    
    def getFormatString(self):
        return ['s00', 's10', 's20', 's30', 's40', 's01', 's11', 's21', 's31', 's41',
                's02', 's12', 's22', 's32', 's42', 's03', 's13', 's23', 's33', 's43']
    
    def createSTP(self, filename, cipherParameters):
        """
        Creates an STP file to find a preimage for Keccak.
        """        
        wordsize = cipherParameters[0]
        rate = cipherParameters[1]
        capacity = cipherParameters[2]
        rounds = cipherParameters[3]
        iterative = cipherParameters[4]
        varsFixed = cipherParameters[5]
        
        with open(filename, 'w') as file:
            file.write("% Input File for STP\n% Keccak w={} rate={} capacity={}\n\n\n".format(wordsize, rate, capacity, rounds))
               
            # Setup variables
            # 5x5 lanes x
            s = ["s{}{}{}".format(x,y, i) for i in range(rounds + 1) for y in range(5) for x in range(5)] 
            a = ["a{}{}{}".format(x,y, i) for i in range(rounds + 1) for y in range(5) for x in range(5)]
            b = ["b{}{}{}".format(x,y, i) for i in range(rounds + 1) for y in range(5) for x in range(5)]
            c = ["c{}{}".format(x, i) for i in range(rounds + 1) for x in range(5) ]
            d = ["d{}{}".format(x, i) for i in range(rounds + 1) for x in range(5) ]
            
            
            StpCommands().setupVariables(file, s, wordsize)
            StpCommands().setupVariables(file, a, wordsize)
            StpCommands().setupVariables(file, b, wordsize)
            StpCommands().setupVariables(file, c, wordsize)
            StpCommands().setupVariables(file, d, wordsize)
            
            #Fix variables for capacity, only works if rate/capacity is multiple of wordsize
            for i in range(rate / wordsize, (rate + capacity) / wordsize):
                StpCommands().assertVariableValue(file, s[i] , "0hex{}".format("0"*(wordsize / 4)))
               
            for round in range(rounds):
                self.setupKeccakRound(file, round, s, a, b, c, d, wordsize)
                       
            if(varsFixed):
                for key, value in varsFixed.iteritems():
                    StpCommands().assertVariableValue(file, key, value)
                                
            StpCommands().setupQuery(file)

        return
    
    def constructParametersList(self, rounds, wordsize, weight):
        """
        TODO:
        """
        return [wordsize, 240, 160, rounds]
    
        
    def setupKeccakRound(self, file, round, s, a, b, c, d, wordsize):
        file.write(self.getStringForKeccakRound(round, s, a, b, c, d, wordsize) + '\n')
        return
    
    
    def getStringForKeccakRound(self, round, s, a, b, c, d, wordsize):
        """
        Returns a string representing one round of Keccak in STP.
        """
        
        command = ""
                    
        #Compute Parity for each column
        for i in range(5):                               
            command += "ASSERT({} = BVXOR({}, BVXOR({}, BVXOR({}, BVXOR({}, {})))));\n".format(
                           c[i + 5*round], s[i + 5*0 + 25*round], s[i + 5*1 + 25*round],
                           s[i + 5*2 + 25*round], s[i + 5*3 + 25*round], s[i + 5*4 + 25*round])

        #Compute intermediate values
        for i in range(5):                               
            command += "ASSERT({} = BVXOR({}, {}));\n".format(d[i + 5*round], c[(i - 1) % 5 + 5*round], 
                            StpCommands().getStringLeftRotate(c[(i + 1) % 5 + 5*round], 1, wordsize))
            
        #Rho and Pi
        for x in range(5):
            for y in range(5):
                #x + 5*y + 25*round -> y + 5*((2*x + 3*y) % 5) + 25*round
                newIndexB = y + 5*((2*x + 3*y) % 5) + 25*round
                tmpXOR = "BVXOR({}, {})".format(s[x + 5*y + 25*round], d[x + 5*round])
                command += "ASSERT({} = {});\n".format(b[newIndexB], StpCommands().getStringLeftRotate(tmpXOR, self.ro[x][y], wordsize))
                   
                   
        #Chi
        for x in range(5):
            for y in range(5):
                chiTmp = "BVXOR({}, ~{} & {})".format(b[(x + 0) % 5 + 5*y + 25*round], 
                                                      b[(x + 1) % 5 + 5*y + 25*round], 
                                                      b[(x + 2) % 5 + 5*y + 25*round])
                command += "ASSERT({} = {});\n".format(a[x + 5*y + 25*round], chiTmp)
                
        #Add round constant
        for x in range(5):
            for y in range(5):
                if(x == 0 and y == 0):
                    command += "ASSERT({} = BVXOR({}, {}));\n".format(s[25*(round + 1)], a[25*round], self.rc[round])
                else:
                    command += "ASSERT({} = {});\n".format(s[x + 5*y + 25*(round + 1)], a[x + 5*y + 25*round])
                                                 
        return command

    
    