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
                    header.append(word)
                else:
                    try:
                        # Add word to table
                        if(word == 'w'):
                            weight = self.characteristicData[word+str(round)]
                            tmpRow.append("-" + str(bin(int(weight, 16)).count('1')))
                        else:
                            tmpRow.append(self.characteristicData[word+str(round)])
                    except KeyError, e:
                        tmpRow.append("none")
            if(tmpRow):
                data.append(tmpRow)
            
        # Print 
        columnWidth = max(len(s) for s in list(itertools.chain.from_iterable(data))) + 2
        headerString = "Rounds\t"
        dataString = ""
        currentRow = 0
        
        for entry in header:
            headerString += entry.ljust(columnWidth)
        for row in data:
            dataString += str(currentRow) + '\t'
            currentRow += 1
            for entry in row:
                dataString += entry.ljust(columnWidth)
            dataString += '\n'
            
            
        
        print headerString
        print "-"*len(headerString)
        print dataString
        
        return
    
    def printLatex(self):
        '''
        Prints latex table using booktabs
        '''
        print "not implemented yet"
        return
        
        
    

         