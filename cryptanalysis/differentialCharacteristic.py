'''
Created on Apr 25, 2014

@author: stefan
'''

import itertools

class differentialCharacteristic:
    '''
    This class represents a single differential characteristic.
    '''

    characteristicData = None
    printFormat = None
    numberOfRounds = 0
     
    def __init__(self, data, format, rounds):
        self.characteristicData = data
        self.printFormat = format 
        self.numberOfRounds = rounds
        return
    
    def printText(self):
        '''
        Prints a table from the data structure.
        TODO: maybe use prettytable?
        '''
        header = []
        data = []
        
        # Get data
        for round in range(-1, self.numberOfRounds + 1):
            tmpRow = []
            for word in self.printFormat:
                if(round == -1):
                    #Print Header
                    header.append(word)
                else:
                    try:
                        tmpRow.append(self.characteristicData[word+str(round)])
                    except KeyError, e:
                        tmpRow.append("no value")
            if(tmpRow):
                data.append(tmpRow)
            
        # Print 
        columnWidth = max(len(s) for s in list(itertools.chain.from_iterable(data))) + 2
        headerString = ""
        dataString = ""
        for entry in header:
            headerString += entry.ljust(columnWidth)
        for row in data:
            for entry in row:
                dataString += entry.ljust(columnWidth)
            dataString += '\n'
            
        
        print headerString
        print "-"*columnWidth*len(header)
        print dataString
        
        return
    
    def printLatex(self):
        '''
        Prints latex table using booktabs
        '''
        print "not implemented yet"
        return
        
        
    

         