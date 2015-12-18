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
    cipher = None

    def __init__(self, data, cipher, rounds, weight):
        self.characteristic_data = data
        self.print_format = cipher.getFormatString()
        self.num_rounds = rounds
        self.weight = weight
        self.cipher = cipher
        return

    def getData(self):
        """
        Get the data as a list.
        """
        data = []
        # Get data
        for rnd in range(0, (self.num_rounds + 1) * self.msg_blocks):
            tmp_row = []
            for word in self.print_format:
                try:
                    # Add word to table
                    if word == 'w':
                        weight = self.characteristic_data[word+str(rnd)]
                        # Print hw(weight) or weight depending on the cipher
                        if self.cipher.name == "keccakdiff" or \
                           self.cipher.name == "ketje" or \
                           self.cipher.name == "ascon":
                            tmp_row.append("-" + str(int(weight, 16)))
                        else:
                            tmp_row.append("-" + str(bin(int(weight, 16)).count('1')))
                    else:
                        tmp_row.append(self.characteristic_data[word+str(rnd)])
                except KeyError:
                    tmp_row.append("none")
            if tmp_row:
                data.append(tmp_row)
        return data

    def printText(self):
        """
        Prints a table from the data structure.
        """
        header = []
        data = self.getData()

        # Get header
        for word in self.print_format:
            header.append(word)

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

        print(header_str)
        print("-"*len(header_str))
        print(data_str)
        print("Weight: " + str(int(self.weight, 16)))
        return

    def getDOTString(self):
        """
        Get the trail in .dot compatible format.
        """
        result = ""
        data = self.getData()

        last_node = ""
        last_probability = None
        for idx, entry in enumerate(data):
            new_node = "rnd{}".format(idx)
            for value in entry[:-1]: # Last entry should always be weight
                new_node += str(value)

            # Add label shortended to first two values
            result += new_node + " [label=\"{},{}\"];\n".format(entry[0], entry[1]) 
            if last_node != "":
                # Add edge
                result += "{} -> {} [label=\"{}\"];\n".format(last_node, new_node, last_probability)
            last_probability = entry[2]
            last_node = new_node
        return result

    def printDOT(self):
        """
        Print the trail as a graph in .dot format.
        """
        
        print("digraph graphname {")
        print(self.getDOTString())
        print("}")
        return

    def getTexString(self):
        """
        Get the trail as a .tex table.
        """
        header = ["Round"]
        data = self.getData()

        # Get header
        for word in self.print_format:
            header.append(word)

        result = "\\documentclass{standalone}\n\n"
        result += "\\usepackage{booktabs}\n\n"
        result += "\\begin{document}\n"
        result += "\\begin{tabular}{" + ("c" * (len(header) + 1)) + "}\n"
        result += "\\toprule\n"

        header_string = ""
        for label in header:
            header_string += label + " & "
        result += header_string[:-2] + "\\\\\n"
        
        result += "\\midrule\n"

        for idx, entry in enumerate(data):
            tmp_row = "${}$ & ".format(idx)
            for value in entry:
                tmp_row += "\\texttt{" + str(value) + "} & "
            result += tmp_row[:-2] + "\\\\\n"

        result += "\\bottomrule\n"
        result += "\\end{tabular}\n"
        result += "\\end{document}\n"




        return result
