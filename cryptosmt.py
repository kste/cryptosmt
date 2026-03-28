'''
Created on Mar 28, 2014

@author: stefan
'''

# Structured configuration refactoring
from cryptanalysis import search
import ciphers
from config import PATH_STP, PATH_CRYPTOMINISAT, PATH_BOOLECTOR, PATH_BITWUZLA

from argparse import ArgumentParser, RawTextHelpFormatter
from dataclasses import dataclass, field, asdict
from typing import Dict, List, Optional, Any

import yaml
import os
import logging

logger = logging.getLogger("cryptosmt")

@dataclass
class ToolParameters:
    cipher: str = "simon"
    rounds: int = 5
    mode: int = 0
    wordsize: int = 16
    blocksize: int = 64
    tweaksize: Optional[int] = None
    keysize: Optional[int] = None
    sweight: int = 0
    endweight: int = 1000
    iterative: bool = False
    boolector: bool = False
    bitwuzla: bool = False
    stp: bool = False
    weightencoding: str = "bvplus"
    threads: int = 1
    dot: Optional[str] = None
    latex: Optional[str] = None
    nummessages: int = 1
    timelimit: int = -1
    fixedVariables: Dict[str, str] = field(default_factory=dict)
    blockedCharacteristics: List[Any] = field(default_factory=list)
    rotationconstants: Optional[List[int]] = None
    verbose: bool = False
    quiet: bool = False
    list_ciphers: bool = False


def startsearch(params: ToolParameters):
    """
    Starts the search tool for the given parameters
    """

    if params.list_ciphers:
        cipher_suite = ciphers.get_cipher_suite()
        print("Available ciphers:")
        for name in sorted(cipher_suite.keys()):
            print(f"  - {name}")
        return

    cipher = ciphers.get_cipher(params.cipher)

    if cipher is None:
        logger.error(f"Cipher {params.cipher} not supported!")
        return

    # Structured dictionary for cipher/search modules
    params_dict = asdict(params)
    
    # Optional fields removal logic
    if params.rotationconstants is None:
        del params_dict["rotationconstants"]
    
    # Remove CLI-only fields
    for field_name in ["verbose", "quiet", "list_ciphers"]:
        if field_name in params_dict:
            del params_dict[field_name]

    # Handle program flow
    if params.mode == 0:
        search.findMinWeightCharacteristic(cipher, params_dict)
    elif params.mode == 1:
        search.searchCharacteristics(cipher, params_dict)
    elif params.mode == 2:
        search.findAllCharacteristics(cipher, params_dict)
    elif params.mode == 3:
        search.findBestConstants(cipher, params_dict)
    elif params.mode == 4:
        search.computeProbabilityOfDifferentials(cipher, params_dict)

    return

def checkenviroment():
    """
    Basic checks if the enviroment is set up correctly
    """

    if not os.path.exists("./tmp/"):
        os.makedirs("./tmp/")

    if not os.path.exists(PATH_STP):
        logger.error(f"Could not find STP binary at {PATH_STP}, please check config.py")
        exit()

    if not os.path.exists(PATH_CRYPTOMINISAT):
        logger.warning(f"Could not find CRYPTOMINISAT binary at {PATH_CRYPTOMINISAT}, please check config.py.")

    if not os.path.exists(PATH_BOOLECTOR):
        logger.warning(f"Could not find BOOLECTOR binary at {PATH_BOOLECTOR}, \"--boolector\" option not available.")

    if not os.path.exists(PATH_BITWUZLA):
        logger.warning(f"Could not find BITWUZLA binary at {PATH_BITWUZLA}, \"--bitwuzla\" option not available.")

    return


def loadparameters(args) -> ToolParameters:
    """
    Get parameters from the argument list and inputfile.
    """
    params = ToolParameters()

    # Check if there is an input file specified
    if args.inputfile:
        with open(args.inputfile[0], 'r') as input_file:
            doc = yaml.load(input_file, Loader=yaml.SafeLoader)
            
            # Update params from yaml
            for key, value in doc.items():
                if hasattr(params, key):
                    if key == "fixedVariables":
                        fixed_vars = {}
                        for variable in value:
                            fixed_vars.update(variable)
                        params.fixedVariables = fixed_vars
                    else:
                        setattr(params, key, value)

    # Override parameters if they are set on commandline
    if args.cipher is not None:
        params.cipher = args.cipher[0]

    if args.rounds is not None:
        params.rounds = args.rounds[0]

    if args.wordsize is not None:
        params.wordsize = args.wordsize[0]

    if args.blocksize is not None:
        params.blocksize = args.blocksize[0]        

    if args.tweaksize is not None:
        params.tweaksize = args.tweaksize[0]

    if args.keysize is not None:
        params.keysize = args.keysize[0]

    if args.sweight is not None:
        params.sweight = args.sweight[0]

    if args.endweight is not None:
        params.endweight = args.endweight[0]

    if args.mode is not None:
        params.mode = args.mode[0]

    if args.timelimit is not None:
        params.timelimit = args.timelimit[0]

    if args.iterative:
        params.iterative = args.iterative

    if args.boolector:
        params.boolector = args.boolector

    if args.bitwuzla:
        params.bitwuzla = args.bitwuzla

    if args.stp:
        params.stp = args.stp

    if args.weightencoding:
        params.weightencoding = args.weightencoding

    if args.threads is not None:
        params.threads = args.threads[0]

    if args.nummessages is not None:
        params.nummessages = args.nummessages[0]

    if args.dot is not None:
        params.dot = args.dot[0]

    if args.latex is not None:
        params.latex = args.latex[0]

    if args.verbose:
        params.verbose = args.verbose
    
    if args.quiet:
        params.quiet = args.quiet

    if args.list_ciphers:
        params.list_ciphers = args.list_ciphers

    return params


def main():
    """
    Parse the arguments and start the request functionality with the provided
    parameters.
    """
    parser = ArgumentParser(description="This tool finds the best differential"
                                        "trail in a cryptopgrahic primitive"
                                        "using STP and CryptoMiniSat.",
                            formatter_class=RawTextHelpFormatter)

    parser.add_argument('--cipher', nargs=1, help="Options: simon, speck, ...")
    parser.add_argument('--sweight', nargs=1, type=int,
                        help="Starting weight for the trail search.")
    parser.add_argument('--endweight', nargs=1, type=int,
                        help="Stop search after reaching endweight.")    
    parser.add_argument('--rounds', nargs=1, type=int,
                        help="The number of rounds for the cipher")
    parser.add_argument('--wordsize', nargs=1, type=int,
                        help="Wordsize used for the cipher.")
    parser.add_argument('--blocksize', nargs=1, type=int,
                        help="Blocksize used for the cipher.")    
    parser.add_argument('--tweaksize', nargs=1, type=int,
                        help="Tweaksize used for the cipher (e.g. for Skinny).")
    parser.add_argument('--keysize', nargs=1, type=int,
                        help="Keysize used for the cipher.")
    parser.add_argument('--nummessages', nargs=1, type=int,
                        help="Number of message blocks.")
    parser.add_argument('--mode', nargs=1, type=int, 
                        choices=[0, 1, 2, 3, 4], help=
                        "0 = search characteristic for fixed round\n"
                        "1 = search characteristic for all rounds starting at"
                        "the round specified\n"
                        "2 = search all characteristic for a specific weight\n"
                        "3 = used for key recovery\n"
                        "4 = determine the probability of the differential\n")
    parser.add_argument('--timelimit', nargs=1, type=int,
                        help="Set a timelimit for the search in seconds.")
    parser.add_argument('--iterative', action="store_true",
                        help="Only search for iterative characteristics")
    parser.add_argument('--boolector', action="store_true",
                        help="Use boolector to find solutions")
    parser.add_argument('--bitwuzla', action="store_true",
                        help="Use bitwuzla to find solutions")
    parser.add_argument('--stp', action="store_true",
                        help="Use STP to find solutions (default)")
    parser.add_argument('--weightencoding', choices=['bvplus', 'sorter', 'totalizer'], 
                        default='bvplus', help="Encoding used for weight computation.")
    parser.add_argument('--threads', nargs=1, type=int, default=[1],
                        help="Number of threads to use for parallel search.")
    parser.add_argument('--inputfile', nargs=1, help="Use an yaml input file to"
                                                     "read the parameters.")
    parser.add_argument('--dot', nargs=1, help="Print the trail in .dot format.")
    parser.add_argument('--latex', nargs=1, help="Print the trail in .tex format.")
    parser.add_argument('--verbose', action="store_true", help="Show verbose output")
    parser.add_argument('--quiet', action="store_true", help="Show only results")
    parser.add_argument('--list-ciphers', action="store_true", help="List all available ciphers")

    # Parse command line arguments and construct parameter list.
    args = parser.parse_args()
    params = loadparameters(args)

    # Set up logging
    log_level = logging.INFO
    if params.verbose:
        log_level = logging.DEBUG
    elif params.quiet:
        log_level = logging.WARNING
    
    logging.basicConfig(level=log_level, format='%(levelname)s: %(message)s')

    # Check if enviroment is setup correctly.
    checkenviroment()

    # Start the solver
    startsearch(params)


if __name__ == '__main__':
    main()
