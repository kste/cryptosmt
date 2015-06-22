'''
Created on Mar 28, 2014

@author: stefan
'''

from cryptanalysis import search
from ciphers import (simon, speck, simonlinear, keccak, siphash, simonrk,
                     chaskeymachalf, simonkeyrc, keccakcollision)
from config import *

from argparse import ArgumentParser, RawTextHelpFormatter

import yaml
import os


def startsearch(tool_parameters):
    """
    Starts the search tool for the given parameters
    """

    # Select Cipher Cipher
    if tool_parameters["cipher"] == 'simon':
        cipher = simon.SimonCipher()
    elif tool_parameters["cipher"] == 'speck':
        cipher = speck.SpeckCipher()
    elif tool_parameters["cipher"] == 'simonlinear':
        cipher = simonlinear.SimonLinearCipher()
    elif tool_parameters["cipher"] == 'keccak':
        cipher = keccak.KeccakCipher()
    elif tool_parameters["cipher"] == 'keccakcollision':
        cipher = keccakcollision.KeccakCollisionCipher()
    elif tool_parameters["cipher"] == 'siphash':
        cipher = siphash.SipHashCipher()
    elif tool_parameters["cipher"] == 'simonrk':
        cipher = simonrk.SimonRkCipher()
    elif tool_parameters["cipher"] == 'simonkeyrc':
        cipher = simonkeyrc.SimonKeyRcCipher()
    elif tool_parameters["cipher"] == 'chaskeyhalf':
        cipher = chaskeymachalf.ChasKeyMacHalf()
    else:
        print "Cipher not supported!"
        return

    # Handle program flow
    if tool_parameters["mode"] == 0:
        search.findMinWeightCharacteristic(cipher, tool_parameters)
    elif tool_parameters["mode"] == 1:
        search.searchCharacteristics(cipher, tool_parameters)
    elif tool_parameters["mode"] == 2:
        search.findAllCharacteristics(cipher, tool_parameters)
    elif tool_parameters["mode"] == 3:
        search.findBestConstants(cipher, tool_parameters)
    elif tool_parameters["mode"] == 4:
        search.computeProbabilityOfDifferentials(cipher, tool_parameters)

    return


def checkparameters(params):
    """
    Checks the parameters and sets default values if no
    value was given.
    """
    if not "iterative" in params:
        params["iterative"] = False

    if not "fixedVariables" in params:
        params["fixedVariables"] = None

    if not "sweight" in params:
        params["sweight"] = 0

    if not "rounds" in params:
        params["rounds"] = 5

    if not "mode" in params:
        params["mode"] = 0

    if not "wordsize" in params:
        params["wordsize"] = 16

    if not "boolector" in params:
        params["boolector"] = False

    if not "nummessages" in params:
        params["nummessages"] = 1

    return

def checkenviroment():
    """
    Basic checks if the enviroment is set up correctly
    """

    if not os.path.exists("./tmp/"):
        os.makedirs("./tmp/")

    if not os.path.exists(PATH_STP):
        print "ERROR: Could not find STP binary, please check config.py"
        exit()

    if not os.path.exists(PATH_CRYPTOMINISAT):
        print "WARNING: Could not find CRYPTOMINISAT binary, please check config.py."

    if not os.path.exists(PATH_BOOLECTOR):
        print "WARNING: Could not find BOOLECTOR binary, \"--boolector\" option not available."

    return


def loadparameters(args):
    """
    Get parameters from the argument list and inputfile.
    """
    params = {}
    # Check if there is an input file specified
    if args.inputfile:
        with open(args.inputfile[0], 'r') as input_file:
            doc = yaml.load(input_file)
            if "rounds" in doc:
                params["rounds"] = doc["rounds"]
            if "cipher" in doc:
                params["cipher"] = doc["cipher"]
            if "wordsize" in doc:
                params["wordsize"] = doc["wordsize"]
            if "msgblocks" in doc:
                params["msgblocks"] = doc["msgblocks"]
            if "mode" in doc:
                params["mode"] = doc["mode"]
            if "iterative" in doc:
                params["iterative"] = doc["iterative"]
            if "sweight" in doc:
                params["sweight"] = doc["sweight"]
            if "nummessages" in doc:
                params["nummessages"] = doc["nummessages"]
            if "boolector" in doc:
                params["boolector"] = doc["boolector"]
            if "fixedVariables" in doc:
                fixed_vars = {}
                for variable in doc["fixedVariables"]:
                    fixed_vars = dict(fixed_vars.items() + variable.items())
                params["fixedVariables"] = fixed_vars

    # Override parameters if they are set on commandline
    if args.cipher:
        params["cipher"] = args.cipher[0]

    if args.rounds:
        params["rounds"] = int(args.rounds[0])

    if args.wordsize:
        params["wordsize"] = int(args.wordsize[0])

    if args.sweight:
        params["sweight"] = int(args.sweight[0])

    if args.mode:
        params["mode"] = int(args.mode[0])

    if args.iterative:
        params["iterative"] = args.iterative

    if args.boolector:
        params["boolector"] = args.boolector

    if args.nummessages:
        params["nummessages"] = int(args.nummessages[0])

    return params


def main():
    """
    Parse the arguments and start the request functionality with the provided
    parameters.
    """
    parser = ArgumentParser(description="This tool finds the best differential"
                                        "characteristics for a specific hamming"
                                        "weight using STP and CryptoMiniSat.",
                            formatter_class=RawTextHelpFormatter)

    parser.add_argument('--cipher', nargs=1, help="Options: simon, speck, ...")
    parser.add_argument('--sweight', nargs=1, help="Hamming weight of the"
                                                   "characteristic to search")
    parser.add_argument('--rounds', nargs=1, help="The number of rounds for"
                                                  "the cipher")
    parser.add_argument('--wordsize', nargs=1, help="Wordsize used for the"
                                                    "cipher.")
    parser.add_argument('--nummessages', nargs=1,
                        help="Number of message blocks.")
    parser.add_argument('--mode', nargs=1, help=
                        "0 = search characteristic for fixed round\n"
                        "1 = search characteristic for all rounds starting at"
                        "the round specified\n"
                        "2 = search all characteristic for a specific weight\n"
                        "3 = used for key recovery\n"
                        "4 = determine the probability of the differential\n")
    parser.add_argument('--iterative', action="store_true",
                        help="Only search for iterative characteristics")
    parser.add_argument('--boolector', action="store_true",
                        help="Use boolector to find solutions")
    parser.add_argument('--inputfile', nargs=1, help="Use an yaml input file to"
                                                     "read the parameters.")

    # Parse command line arguments and construct parameter list
    args = parser.parse_args()
    params = loadparameters(args)

    # Check parameter sanity and set default values
    checkparameters(params)
    checkenviroment()

    # Start the solver
    startsearch(params)


if __name__ == '__main__':
    main()
