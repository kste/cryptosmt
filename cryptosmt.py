'''
Created on Mar 28, 2014

@author: stefan
'''

from cryptanalysis import characteristicSearch, differentialSearch
from ciphers import simon, speck, simonlinear, keccak, siphash, simonrk, chaskeymac, chaskeymachalf, simonkeyrc

from argparse import RawTextHelpFormatter

import argparse
import yaml

# Paths to the STP and cryptominisat executable
pathToSTP = "../stp/stp"
pathToCryptoMinisat = "../cryptominisat/cryptominisat"
pathToBoolector = "../boolector/boolector/boolector"


def startTool(toolParameters):
    """
    Starts the search tool for the given parameters
    """
    search = characteristicSearch.characteristicSearch(pathToSTP, pathToBoolector)
    searchDifferential = differentialSearch.differentialSearch(pathToSTP, pathToCryptoMinisat)
       
    # Cipher
    if(toolParameters["cipher"] == 'simon'):
        cipher = simon.SimonCipher()
    elif(toolParameters["cipher"] == 'speck'):
        cipher = speck.SpeckCipher()
    elif(toolParameters["cipher"] == 'simonlinear'):
        cipher = simonlinear.SimonLinearCipher()
    elif(toolParameters["cipher"] == 'keccak'):
        cipher = keccak.KeccakCipher()
    elif(toolParameters["cipher"] == 'siphash'):
        cipher = siphash.SipHashCipher(toolParameters["msgblocks"]) 
    elif(toolParameters["cipher"] == 'simonrk'):
        cipher = simonrk.SimonRkCipher()
    elif(toolParameters["cipher"] == 'simonkeyrc'):
        cipher = simonkeyrc.SimonKeyRcCipher()        
    elif(toolParameters["cipher"] == 'chaskey'):
        cipher = chaskeymac.ChasKeyMac(toolParameters["msgblocks"])
    elif(toolParameters["cipher"] == 'chaskeyhalf'):
        cipher = chaskeymachalf.ChasKeyMacHalf(toolParameters["msgblocks"])         
    else:
        print "Cipher not supported!"
        return
    
    #handle program flow
    if(toolParameters["mode"] == 0):
        search.findMinWeightCharacteristic(cipher, toolParameters)
   
    if(toolParameters["mode"] == 1):
        search.searchCharacteristics(cipher, toolParameters)
    
    if(toolParameters["mode"] == 2):
        search.findAllCharacteristics(cipher, toolParameters) 
    
    if(toolParameters["mode"] == 3):
        search.findBestConstants(cipher, toolParameters)
    
    if(toolParameters["mode"] == 4):
        searchDifferential.computeProbabilityOfDifferentials(cipher, toolParameters)

    return

def checkParameters(params):
    """
    Checks the parameters and sets default values if no 
    value was given.
    """
    if not ("iterative" in params):
        params["iterative"] = False
        
    if not ("fixedVariables" in params):
        params["fixedVariables"] = None
        
    if not ("sweight" in params):
        params["sweight"] = 0
    
    if not ("rounds" in params):
        params["rounds"] = 5

    if not ("msgblocks" in params):
        params["msgblocks"] = 1
        
    if not ("mode" in params):
        params["mode"] = 0
        
    if not ("wordsize" in params):
        params["wordsize"] = 16

    if not ("boolector" in params):
        params["boolector"] = False

    return

def main():
    """
    Parse the arguments and start the request functionality with the provided parameters.
    """
    parser = argparse.ArgumentParser(description="This tool finds the best differential characteristics, " +
                                     "for a specific hamming weight using STP and CryptoMiniSat.",
                                     formatter_class=RawTextHelpFormatter)
    parser.add_argument('--cipher', nargs=1, help="Options: simon, speck, sha1")
    parser.add_argument('--sweight', nargs=1, help="Hamming weight of the characteristic to search")
    parser.add_argument('--rounds', nargs=1, help="The number of rounds to use of the cipher")
    parser.add_argument('--wordsize', nargs=1, help="Wordsize used in the cipher.")
    parser.add_argument('--msgblocks', nargs=1, help="Number of message blocks.")
    parser.add_argument('--mode', nargs=1, help="0 = search characteristic for fixed round\n" + 
                                                "1 = search characteristic for all rounds starting at the round specified\n" +
                                                "2 = search all characteristic for a specific weight\n" +
                                                "4 = determine the probability of the differential\n")
    parser.add_argument('--iterative', action="store_true", help="Only search for iterative characteristics")
    parser.add_argument('--boolector', action="store_true", help="Use boolector to find solutions")
    parser.add_argument('--inputfile', nargs=1, help="Use an yaml input file to read the parameters.")
    
    args = parser.parse_args()
    
    # default values for the parameters
    params = {}
    
    # check if there is an input file
    if(args.inputfile):
        with open(args.inputfile[0], 'r') as f:
            doc = yaml.load(f)
            if("rounds" in doc):
                params["rounds"] = doc["rounds"]
            if("cipher" in doc):
                params["cipher"] = doc["cipher"]
            if("wordsize" in doc):
                params["wordsize"] = doc["wordsize"]
            if("msgblocks" in doc):
                params["msgblocks"] = doc["msgblocks"]
            if("mode" in doc):
                params["mode"] = doc["mode"]
            if("iterative" in doc):
                params["iterative"] = doc["iterative"]
            if("sweight" in doc):
                params["sweight"] = doc["sweight"]
            if("fixedVariables" in doc):
                fixedVars = {}
                for variable in doc["fixedVariables"]:
                    fixedVars = dict(fixedVars.items() + variable.items())
                params["fixedVariables"] = fixedVars
                
    
    # override parameters if flags are set
    
    if(args.cipher):
        params["cipher"] = args.cipher[0]
        
    if(args.rounds):
        params["rounds"] = int(args.rounds[0])
        
    if(args.wordsize):
        params["wordsize"] = int(args.wordsize[0])
    
    if(args.sweight):
        params["sweight"] = int(args.sweight[0])

    if(args.msgblocks):
        params["msgblocks"] = int(args.msgblocks[0])
        
    if(args.mode):
        params["mode"] = int(args.mode[0])
        
    if(args.iterative):
        params["iterative"] = args.iterative

    if(args.boolector):
        params["boolector"] = args.boolector
        
    #check parameter sanity and set default values
    checkParameters(params)
    startTool(params)
    pass
    

if __name__ == '__main__':
    main()