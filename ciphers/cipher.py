'''
Created on Mar 25, 2014

@author: stefan
'''

from abc import ABCMeta, abstractmethod
from parser import stpcommands

class AbstractCipher(object, metaclass=ABCMeta):
    """
    Abstract Class for Ciphers
    """

    def __init__(self):
        self.state_variables = []
        self.weight_variables = []

    @property
    @abstractmethod
    def name(self):
        """
        Return the name of the cipher.
        """
        pass

    @abstractmethod
    def getFormatString(self):
        """
        Each cipher needs to specify the format it should be printed.
        """
        pass

    def createSTP(self, filename, parameters):
        """
        Template method to create an STP file.
        This is only used by refactored ciphers that don't override createSTP.
        """
        self.state_variables = []
        self.weight_variables = []
        
        self.validate_parameters(parameters)
        
        with open(filename, 'w') as stp_file:
            self.write_header(stp_file, parameters)
            self.setup_variables(stp_file, parameters)
            self.apply_constraints(stp_file, parameters)
            self.apply_common_constraints(stp_file, parameters)
            self.setup_query(stp_file, parameters)

    def validate_parameters(self, parameters):
        """
        Subclasses can override this to validate or modify parameters.
        """
        pass

    def write_header(self, stp_file, parameters):
        """
        Writes the header for the STP file.
        """
        header = f"% Input File for STP\n% {self.name} rounds={parameters['rounds']}\n\n\n"
        stp_file.write(header)

    def setup_variables(self, stp_file, parameters):
        """
        Default implementation for setting up variables.
        Subclasses should call helpers like declare_variable_vector.
        """
        pass

    def apply_constraints(self, stp_file, parameters):
        """
        Template for applying constraints. 
        Most ciphers follow a round-based structure.
        """
        rounds = parameters["rounds"]
        weight = parameters["sweight"]
        wordsize = parameters["wordsize"]

        # Setup weight computation if weight variables were registered
        if self.weight_variables:
            ignore_msbs = parameters.get("ignore_msbs", 0)
            encoding = parameters.get("weightencoding", "bvplus")
            # Use blocksize for weight if specified (Skinny/Rectangle)
            w_size = wordsize
            if self.name in ["skinny", "rectangle"]:
                w_size = parameters.get("blocksize", 64)
            stpcommands.setupWeightComputation(stp_file, weight, self.weight_variables, w_size, ignore_msbs, encoding)

        # Standard round loop
        for i in range(rounds):
            self.apply_round_constraints(stp_file, i, parameters)

    def apply_round_constraints(self, stp_file, round_nr, parameters):
        """
        Subclasses implement the logic for a single round here.
        """
        pass

    def apply_common_constraints(self, stp_file, parameters):
        """
        Apply constraints common to most ciphers.
        """
        # Non-zero constraint
        if self.state_variables:
            size = parameters.get("wordsize", 16)
            if self.name in ["skinny", "rectangle"]:
                size = parameters.get("blocksize", 64)
            stpcommands.assertNonZero(stp_file, self.state_variables, size)
            
            # Simple implication: if state is 0, next state can't be 0 unless all zero
            # This is a bit redundant with non-zero but can help some solvers.
            # (Experimental)

        # Iterative constraint
        if parameters.get("iterative"):
            self.apply_iterative_constraints(stp_file, parameters)

        # Fixed variables
        for key, value in parameters.get("fixedVariables", {}).items():
            stpcommands.assertVariableValue(stp_file, key, value)

        # Blocked characteristics
        for char in parameters.get("blockedCharacteristics", []):
            stpcommands.blockCharacteristic(stp_file, char, size)

    def apply_iterative_constraints(self, stp_file, parameters):
        """
        Default iterative constraint assumes self.x and self.y (etc) 
        are lists of variables where [0] is input and [rounds] is output.
        """
        pass

    def setup_query(self, stp_file, parameters):
        """
        Finalize the STP file with a query.
        """
        stpcommands.setupQuery(stp_file)

    # Helper methods for subclasses
    def declare_variable_vector(self, stp_file, prefix, rounds, wordsize, is_state=False):
        """
        Helper to declare a vector of variables.
        """
        vars = [f"{prefix}{i}" for i in range(rounds + 1)]
        stpcommands.setupVariables(stp_file, vars, wordsize)
        if is_state:
            self.state_variables.extend(vars)
        return vars

    def declare_variable_vector_per_round(self, stp_file, prefix, rounds, wordsize, is_weight=False, is_state=False):
        """
        Helper to declare a vector of variables with one per round.
        """
        vars = [f"{prefix}{i}" for i in range(rounds)]
        stpcommands.setupVariables(stp_file, vars, wordsize)
        if is_weight:
            self.weight_variables.extend(vars)
        if is_state:
            self.state_variables.extend(vars)
        return vars
