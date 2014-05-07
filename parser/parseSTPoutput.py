'''
Created on Mar 28, 2014

@author: stefan
'''

from cryptanalysis import differentialCharacteristic
import re

class parseSTPoutput(object):
    """
    parseSTPoutput provides functions to convert STP output
    """
    
    _instance = None
    def __new__(cls, *args, **kwargs):
        if not cls._instance:
            cls._instance = super(parseSTPoutput, cls).__new__(cls, *args, **kwargs)
        return cls._instance

    def printSTPOutputAsCharacteristic(self, output, characteristicFormat, rounds):
        """
        Takes the STP output and prints it in table form. 
        characteristicFormat gives the order of the words to print
        Example:
        characteristicFormat = ['x', 'y', 'p']
        
        x        y        p
        0x1001   0x0000   0x1001
        0x1001   0x0000   0x1001
        ...
        """
        #print output
        
        characteristic = {}
        
        for row in output.split('\n'):
            if(re.match('ASSERT.*weight', row)):
                weight = re.search('(?<=ASSERT\( weight = ).*(?= \);)',row).group(0)
            elif(re.match('ASSERT\(.*\)', row)):
                tmp = re.search('ASSERT\( ([a-z0-9A-Z]+) = ([a-z0-9A-Z]+)',row)
                varName = tmp.group(1)
                varValue = tmp.group(2)
                characteristic[varName] = varValue

        diffChar = differentialCharacteristic.differentialCharacteristic(characteristic, characteristicFormat, rounds)
        diffChar.printText()
        print "Total Weight: " + str(int(weight, 2))
        return