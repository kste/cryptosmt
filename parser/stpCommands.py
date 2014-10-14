'''
Created on Mar 28, 2014

@author: stefan
'''

import math



class StpCommands(object):
    """
    StpCommands provides functions to construct STP files.
    """
    
    _instance = None
    def __new__(cls, *args, **kwargs):
        if not cls._instance:
            cls._instance = super(StpCommands, cls).__new__(cls, *args, **kwargs)
        return cls._instance
    
    def blockCharacteristic(self, file, characteristic, wordsize):
        """
        Excludes this characteristic from being found.
        """
        #print characteristic.characteristicData
        # Only add state words (x, y)
        
        filteredWords = {k:v for k,v in characteristic.characteristicData.iteritems() 
                            if k.startswith('x') or k.startswith('y')}
        #print filteredWords
        
        blockingStatement = "ASSERT(NOT("
        
        for key, value in filteredWords.iteritems():
            blockingStatement += "BVXOR({}, {}) | ".format(key, value)
        
        blockingStatement = blockingStatement[:-2] + ") = 0hex{});".format("0"*(wordsize / 4)) 
        
        #print blockingStatement
        file.write(blockingStatement)
        return
    
    def setupQuery(self, file):
        """
        Adds the query and printing of counterexample to the stp file.
        """
        file.write("QUERY(FALSE);\n")
        file.write("COUNTEREXAMPLE;\n")
        return
    
    def setupVariables(self, file, variables, wordsize):
        """
        Adds a list of variables to the stp file.
        """
        file.write(self.getStringForVariables(variables, wordsize) + '\n')
        return
        
        
    def assertVariableValue(self, file, a, b):
        """
        Adds an assert that a = b to the stp file.
        """
        file.write("ASSERT({} = {});\n".format(a, b))
        return
    
    def getStringForVariables(self, variables, wordsize):
        """
        Takes as input the variable name, number of variables and the wordsize
        and constructs for instance a string of the form:
        x00, x01, ..., x30: BITVECTOR(wordsize);
        """
        command = ""
        for var in variables:
            command += var + ","  
            
        command = command[:-1]
        command += ": BITVECTOR({0});".format(wordsize)
        return command
    
    def assertNonZero(self, file, variables, wordsize):
        file.write(self.getStringForNonZero(variables, wordsize) + '\n')
        return
        
    def getStringForNonZero(self, variables, wordsize):
        """
        Asserts that no all-zero characteristic is allowed
        """
        command = "ASSERT(NOT(("
        for var in variables:
            command += var + "|"
            
        command = command[:-1]
        command += ") = 0hex{}));".format("0"*(wordsize / 4))
        return command
    
    def setupWeightComputation(self, file, weight, p, wordsize, ignoreMSBs = 0):
        """
        Adds the weight computation and assertion to the stp file.
        """
        file.write("weight: BITVECTOR(16);\n")
        file.write(self.getWeightString(p, wordsize, ignoreMSBs) + "\n")
        file.write("ASSERT(weight = {0:#018b});\n".format(weight))
        return
    
    def getWeightString(self, variables, wordsize, ignoreMSBs = 0):
        """
        Asserts that the weight is equal to the hamming weight of the
        given variables.
        """
        command = "ASSERT((weight = BVPLUS(16,"
        for var in variables:
            tmp = "0b00000000@(BVPLUS(8, "
            for bit in range(wordsize - ignoreMSBs):
                """
                Ignore MSBs if they do not contribute to 
                probability of the characteristic.
                """
                tmp += "0bin0000000@({0}[{1}:{1}]),".format(var, bit, bit)
            command += tmp[:-1] + ")),"
        command = command[:-1]
        command += ")));"
        
        return command
    
    def getStringEq(self, a, b, c, wordsize):
        command = "(BVXOR(~{0}, {1}) & BVXOR(~{0}, {2}))".format(a, b, c)
        return command
    
    def getStringAdd(self, a, b, c, wordsize):
        command = "(((BVXOR((~{0} << 1)[{3}:0], ({1} << 1)[{3}:0])".format(a, b, c, wordsize - 1)
        command += "& BVXOR((~{0} << 1)[{3}:0], ({2} << 1)[{3}:0]))".format(a, b, c, wordsize - 1)
        command += " & BVXOR({0}, BVXOR({1}, BVXOR({2}, ({1} << 1)[{3}:0]))))".format(a, b, c, wordsize - 1)
        command += " = 0hex{})".format("0"*(wordsize / 4))
        return command
    
    def setupSimonRound(self, file, x_in, y_in, x_out, y_out, and_out, p, rotAlpha, rotBeta, rotGamma, wordsize):
        file.write(self.getStringForSimonRound(x_in, y_in, x_out, y_out, and_out, p, rotAlpha, rotBeta, rotGamma, wordsize) + '\n')
        return

    def getStringForSimonRound(self, x_in, y_in, x_out, y_out, and_out, p, rotAlpha, rotBeta, rotGamma, wordsize):
        command = ""
        
        #Assert(y_out = x_in)
        command += "ASSERT({} = {});\n".format(y_out, x_in)
        
        #Assert AND Output
        command += "ASSERT(" + self.getStringForAndDifferential(self.getStringLeftRotate(x_in, rotAlpha, wordsize),
                                                            self.getStringLeftRotate(x_in, rotBeta, wordsize),
                                                            and_out) + " = 0hex{});\n".format("f"*(wordsize / 4))
                                                            
        #Assert XORs
        command += "ASSERT(" + x_out + " = "
        command += "BVXOR("
        command += self.getStringLeftRotate(x_in, rotGamma, wordsize)
        command += ", BVXOR(" + y_in + ", " + and_out + ")"
        command += "));\n"
        
        #For weight computation
        command += "ASSERT({0} = ({1} | {2} | {3})".format(p, self.getStringLeftRotate(x_in, rotAlpha, wordsize),
                                                            self.getStringLeftRotate(x_in, rotBeta, wordsize),
                                                            and_out)
        command += ");" 
        
        return command
    
    def getStringForAndDifferential(self, a, b, c):
        """
        AND = valid(x,y,out) = (x and out) or (y and out) or (not out)
        """
        command = "(({0} & {2}) | ({1} & {2}) | (~{2}))".format(a,b,c)
        return command
    
    def getStringForSHA1RoundF0(self, out, a, b, c, d, e, w):
        command = ""
        
        command += "ASSERT({} = ".format(out)
        command += "BVPLUS(32, 0x5A827999, {}, {}, {},".format(w, self.getStringLeftRotate(a, 5, 32), e)
        command += "(({0} & {1}) | (~{0} & {2}))".format(b, self.getStringLeftRotate(c, 30, 32), d)
        command += "));"

        return command
    
    def getStringForSHA1RoundF1(self, out, a, b, c, d, e, w):
        command = ""
        
        command += "ASSERT({} = ".format(out)
        command += "BVPLUS(32, 0x6ED9EBA1, {}, {}, {},".format(w, self.getStringLeftRotate(a, 5, 32), e)
        command += "BVXOR({}, BVXOR({}, {}))".format(b, self.getStringLeftRotate(c, 30, 32), d)
        command += "));"

        return command
    
    def getStringForSHA1RoundF2(self, out, a, b, c, d, e, w):
        command = ""
        
        command += "ASSERT({} = ".format(out)
        command += "BVPLUS(32, 0x8F1BBCDC, {}, {}, {},".format(w, self.getStringLeftRotate(a, 5, 32), e)
        command += "(({0} & {1}) | ({0} & {2}) | ({1} & {2}))".format(b, self.getStringLeftRotate(c, 30, 32), d)
        command += "));"

        return command
    
    def getStringForSHA1RoundF3(self, out, a, b, c, d, e, w):
        command = ""
        
        command += "ASSERT({} = ".format(out)
        command += "BVPLUS(32, 0xCA62C1D6, {}, {}, {},".format(w, self.getStringLeftRotate(a, 5, 32), e)
        command += "BVXOR({}, BVXOR({}, {}))".format(b, self.getStringLeftRotate(c, 30, 32), d)
        command += "));"

        return command
    
    def getStringForME(self, a, b, c, d, e):
        command = ""
        
        command += "ASSERT({} = ".format(a)
        command += self.getStringLeftRotate("BVXOR({}, BVXOR({}, BVXOR({}, {})))".format(b, c, d, e), 1, 32)
        command += ");"
        return command
    
    def getStringLeftRotate(self, value, rotation, wordsize):
        command = "((({0} << {1})[{2}:0]) | (({0} >> {3})[{2}:0]))".format(value, rotation, wordsize - 1, wordsize - rotation)
        
        return command
    
    def getStringRightRotate(self, value, rotation, wordsize):
        command = "((({0} >> {1})[{2}:0]) | (({0} << {3})[{2}:0]))".format(value, rotation, wordsize - 1, wordsize - rotation)
        return command