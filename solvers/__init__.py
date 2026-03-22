
from .stp import STPSolver
from .bitwuzla import BitwuzlaSolver
from .boolector import BoolectorSolver
from config import PATH_STP, PATH_BITWUZLA, PATH_BOOLECTOR

def get_solver(parameters):
    # If STP is explicitly requested, or if no other solver is specified
    if parameters.get("stp"):
        return STPSolver(PATH_STP)
    if parameters.get("bitwuzla"):
        return BitwuzlaSolver(PATH_BITWUZLA)
    if parameters.get("boolector"):
        return BoolectorSolver(PATH_BOOLECTOR)
    return STPSolver(PATH_STP)
