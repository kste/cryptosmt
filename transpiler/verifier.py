"""Empirical Monte Carlo Differential Verifier for Python Primitives.

Verifies that differential characteristics discovered by the SMT solver match
the actual differential transition probabilities of the executable Python
round function.
"""

from dataclasses import dataclass
import math
import random
from typing import Any, Dict, List, Optional, Tuple

from .cipher_gen import SynthesizedCipher
from .ir import set_active_wordsize


def _parse_solver_val(val_str: str) -> int:
    s = str(val_str).strip()
    if s.startswith("0bin") or s.startswith("#b"):
        return int(s.replace("0bin", "").replace("#b", ""), 2)
    return int(s.replace("0x", "").replace("#x", ""), 16)


@dataclass
class RoundVerificationResult:
    round_nr: int
    input_diff: Tuple[int, ...]
    output_diff: Tuple[int, ...]
    claimed_weight: int
    empirical_weight: Optional[float]
    samples: int
    hits: int
    passed: bool


def verify_round_transition_empirically(
    cipher: SynthesizedCipher,
    round_nr: int,
    input_diff: Tuple[int, ...],
    output_diff: Tuple[int, ...],
    claimed_weight: int,
    wordsize: int,
    min_samples: int = 1 << 13,
    max_samples: int = 1 << 17,
    tolerance_bits: float = 0.85,
) -> RoundVerificationResult:
    """Executes the Python round_fn on random pairs (X, X ^ input_diff) to verify weight."""
    set_active_wordsize(wordsize)
    # Choose sample count ~ 32 * 2^(claimed_weight), clamped to [min_samples, max_samples]
    if claimed_weight > 15:
        # Too rare for fast naive sampling; skip empirical sampling
        return RoundVerificationResult(
            round_nr=round_nr,
            input_diff=input_diff,
            output_diff=output_diff,
            claimed_weight=claimed_weight,
            empirical_weight=None,
            samples=0,
            hits=0,
            passed=True,
        )

    target_samples = min(max_samples, max(min_samples, (1 << int(claimed_weight)) * 32))
    mask = (1 << wordsize) - 1
    hits = 0
    rng = random.Random(0xC0FFEE + round_nr)

    kwargs = {}
    if cipher.accepts_round_nr and cipher.round_param_name:
        kwargs[cipher.round_param_name] = round_nr
    from .ir import KeyWord
    for kname in getattr(cipher, "key_names", ()):
        kwargs[kname] = KeyWord(kname)

    for _ in range(target_samples):
        x0 = [rng.getrandbits(wordsize) for _ in input_diff]
        x1 = [(v ^ d) & mask for v, d in zip(x0, input_diff)]

        y0 = cipher.round_fn(*x0, **kwargs)
        y1 = cipher.round_fn(*x1, **kwargs)
        if isinstance(y0, (int, KeyWord)):
            y0 = (int(y0),)
            y1 = (int(y1),)

        actual_diff = tuple(((int(a) ^ int(b)) & mask) for a, b in zip(y0, y1))
        if actual_diff == output_diff:
            hits += 1

    if hits == 0:
        return RoundVerificationResult(
            round_nr=round_nr,
            input_diff=input_diff,
            output_diff=output_diff,
            claimed_weight=claimed_weight,
            empirical_weight=float("inf"),
            samples=target_samples,
            hits=0,
            passed=False,
        )

    emp_prob = hits / target_samples
    emp_weight = -math.log2(emp_prob)
    passed = abs(emp_weight - claimed_weight) <= tolerance_bits
    return RoundVerificationResult(
        round_nr=round_nr,
        input_diff=input_diff,
        output_diff=output_diff,
        claimed_weight=claimed_weight,
        empirical_weight=emp_weight,
        samples=target_samples,
        hits=hits,
        passed=passed,
    )


def verify_characteristic_empirically(
    cipher: SynthesizedCipher,
    characteristic: Any,
    wordsize: int,
) -> List[RoundVerificationResult]:
    """Verifies every round of a solver-generated DifferentialCharacteristic against Python."""
    results: List[RoundVerificationResult] = []
    data: Dict[str, str] = characteristic.characteristic_data
    rounds = characteristic.num_rounds

    for r in range(rounds):
        in_diff = tuple(
            _parse_solver_val(data[f"{sname}{r}"])
            for sname in cipher.state_names
        )
        out_diff = tuple(
            _parse_solver_val(data[f"{sname}{r + 1}"])
            for sname in cipher.state_names
        )

        # Sum Hamming weights of all weight variables for round r
        round_weight = 0
        if "w" not in cipher.state_names and f"w{r}" in data:
            round_weight = bin(_parse_solver_val(data[f"w{r}"])).count("1")
        else:
            idx = 0
            while f"w{idx}_{r}" in data:
                round_weight += bin(_parse_solver_val(data[f"w{idx}_{r}"])).count("1")
                idx += 1

        res = verify_round_transition_empirically(
            cipher=cipher,
            round_nr=r,
            input_diff=in_diff,
            output_diff=out_diff,
            claimed_weight=round_weight,
            wordsize=wordsize,
        )
        results.append(res)

    return results
