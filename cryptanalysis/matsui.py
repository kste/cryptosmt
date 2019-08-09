'''
Created on Mar 22, 2017

@author: ralph
'''

# imports go here

class MatsuisAlgorithm(object):

    DDT = None

    def procedure_round_1(cipher):
        """
        description of function 
        """
        # create a list of all input differences with hammingweight 1
        allInputDifferences = self.getAllPossibleDifferences(cipher)

        #for each candidate for \delta X1 do the following
        for X1 in allInputDifferences:
            #Let p1 = max_\deltaY (\deltaX1, \deltaY)
            p1 = self.getMaxProbability(cipher, X1)
            #If [p1, B_n-1] >= B_n_dash 
            #if p1*
                #Call procedure_round_2()
                #self.procedure_round_i(2)
        return

    def procedure_round_i(i):
        """
        description of function 
        """
        allOutputDifferences = getAllPossibleDifferences(cipher)

        #For each candidate for \deltaYi do the following
        for Yi in allOutputDifferences:
            #Calculate \deltaXi according to the diffusion layer
            Xi = self.calculateNextInputDifference(Yi, cipher)
            #Calculate the probability pi according to the DDT of the Sbox
            pi = getProbabilityForDifferential(Xi, Yi)
            #If [p1, ..., pi, Bn-i] >= Bndash
                # Call procedure_round_i(i++)
        return

    def procedure_round_n():
        """
        description of function 
        """
        #Calculate \deltaXi according to the diffusion layer
        #Calculate the probability pn according to the DDT of the Sbox
        #If [p1, ..., pi, pn] >= Bndash
            #Bndash = [p1, ..., pi, pn]
        return

    def getAllPossibleDifferences(cipher):
        """
        Returns a list of all differences with hammingweight 1
        """
        return [[1 if i==j else 0 for i in range(cipher.blocksize)] for j in range(cipher.blocksize)]

    def getMaxProbability(cipher, diffIn):
        """
        returns the maximum probability according to a certain input difference
        """
        return

    def calculateNextInputDifference(Yi, cipher):
        """
        Calculate the next input difference according to the output difference and the diffusion layer
        of the cipher
        """
        return

    def getProbabilityForDifferential(Xi, Yi):
        """
        Returns the probability of a differential according to a given input/output difference
        """
        return self.DDT[Xi][Yi]

        return

    def calculateDifferentialDistributionTable(cipher):
        self.DDT = [[0]*len(cipher.sbox) for i in range(len(cipher.sbox))]

        for i in range(len(self.DDT)):
            for j in range(len(self.DDT)):
                self.DDT[i ^ j][cipher.sbox[i] ^ cipher.sbox[j]] += 1




