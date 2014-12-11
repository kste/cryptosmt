'''
Created on Apr 25, 2014

@author: stefan
'''

import itertools


class DifferentialCharacteristic(object):
    '''
    This class represents a single differential characteristic.
    '''

    characteristic_data = None
    print_format = None
    num_rounds = 0
    weight = 0
    msg_blocks = 1

    def __init__(self, data, format, rounds, weight):
        self.characteristic_data = data
        self.print_format = format
        self.num_rounds = rounds
        self.weight = weight
        return

    def printText(self):
        '''
        Prints a table from the data structure.
        '''
        header = []
        data = []

        # Get header
        for word in self.print_format:
            header.append(word)

        # Get data
        for round in range(0, (self.num_rounds + 1) * self.msg_blocks):
            tmp_row = []
            for word in self.print_format:
                try:
                    # Add word to table
                    if word == 'w':
                        weight = self.characteristic_data[word+str(round)]
                        tmp_row.append("-" + str(bin(int(weight, 16)).count('1')))
                    else:
                        tmp_row.append(self.characteristic_data[word+str(round)])
                except KeyError:
                    tmp_row.append("none")
            if tmp_row:
                data.append(tmp_row)

        # Print everthing
        col_width = max(len(s) for s in list(itertools.chain.from_iterable(data))) + 2
        header_str = "Rounds\t"
        data_str = ""
        current_row = 0

        for entry in header:
            header_str += entry.ljust(col_width)
        for row in data:
            data_str += str(current_row) + '\t'
            current_row += 1
            for entry in row:
                data_str += entry.ljust(col_width)
            data_str += '\n'

        print header_str
        print "-"*len(header_str)
        print data_str
        print "Weight: " + str(int(self.weight, 16))
        return

    def printLatex(self):
        '''
        Prints latex table using booktabs
        '''
        print "not implemented yet"
        return
