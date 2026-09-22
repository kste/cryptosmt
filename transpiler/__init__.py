"""Auto-modeling transpiler package for converting Python primitives to CryptoSMT models."""

from .cipher_gen import SynthesizedCipher, build_cipher_from_callable, load_cipher_from_python
from .ir import CipherSpecificationError, KeyWord, SymWord, rotl, rotr
from .verifier import verify_characteristic_empirically, verify_round_transition_empirically

__all__ = [
    "CipherSpecificationError",
    "SynthesizedCipher",
    "build_cipher_from_callable",
    "load_cipher_from_python",
    "KeyWord",
    "SymWord",
    "rotl",
    "rotr",
    "verify_characteristic_empirically",
    "verify_round_transition_empirically",
]
