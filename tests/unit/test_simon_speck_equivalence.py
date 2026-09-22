"""Thorough equivalence verification between hand-written Simon/Speck models and Python-transpiled models."""

import os
import shutil
import sys
import tempfile
import unittest

REPO_ROOT = os.path.abspath(os.path.join(os.path.dirname(__file__), "..", ".."))
sys.path.insert(0, REPO_ROOT)

import config
from ciphers.simon import SimonCipher
from ciphers.speck import SpeckCipher
import solvers.bitwuzla
from solvers.bitwuzla import BitwuzlaSolver
from transpiler import (
    build_cipher_from_callable,
    load_cipher_from_python,
    rotl,
    rotr,
    verify_characteristic_empirically,
)

BITWUZLA_BIN = (
    os.environ.get("CRYPTOSMT_BITWUZLA")
    or shutil.which("bitwuzla")
    or config.PATH_BITWUZLA
)
STP_BIN = (
    os.environ.get("CRYPTOSMT_STP")
    or shutil.which("stp")
    or config.PATH_STP
)


def find_min_weight_and_char(solver, cipher, rounds, wordsize, max_weight=25, extra_params=None):
    """Finds the exact minimum weight and optimal characteristic for a cipher."""
    for w in range(max_weight + 1):
        with tempfile.NamedTemporaryFile(suffix=".stp", delete=False) as tf:
            stp_path = tf.name
        try:
            params = {
                "rounds": rounds,
                "wordsize": wordsize,
                "sweight": w,
                "fixedVariables": {},
                "blockedCharacteristics": [],
            }
            if extra_params:
                params.update(extra_params)
            cipher.createSTP(stp_path, params)
            res = solver.solve(stp_path)
            if res.is_sat:
                char = solver.parse_characteristic(res, cipher, rounds)
                return w, char
        finally:
            if os.path.exists(stp_path):
                os.remove(stp_path)
    raise AssertionError(f"No characteristic found for {cipher.name} (rounds={rounds}) up to weight {max_weight}")


def check_sat_at_weight(solver, cipher, rounds, wordsize, weight, fixed_vars):
    """Checks if a cipher model is SAT at a given weight with fixed state variables."""
    with tempfile.NamedTemporaryFile(suffix=".stp", delete=False) as tf:
        stp_path = tf.name
    try:
        params = {
            "rounds": rounds,
            "wordsize": wordsize,
            "sweight": weight,
            "fixedVariables": fixed_vars,
            "blockedCharacteristics": [],
        }
        cipher.createSTP(stp_path, params)
        res = solver.solve(stp_path)
        return res.is_sat
    finally:
        if os.path.exists(stp_path):
            os.remove(stp_path)


def enumerate_state_trails_at_weight(solver, cipher, rounds, wordsize, weight, fixed_vars, max_trails=20):
    """Enumerates all distinct state trails (x0..xR, y0..yR) at a given weight for fixed endpoints."""
    trails = set()
    blocked = []
    for _ in range(max_trails):
        with tempfile.NamedTemporaryFile(suffix=".stp", delete=False) as tf:
            stp_path = tf.name
        try:
            params = {
                "rounds": rounds,
                "wordsize": wordsize,
                "sweight": weight,
                "fixedVariables": dict(fixed_vars),
                "blockedCharacteristics": list(blocked),
            }
            cipher.createSTP(stp_path, params)
            res = solver.solve(stp_path)
            if not res.is_sat:
                break
            char = solver.parse_characteristic(res, cipher, rounds)
            blocked.append(char)
            state_tuple = tuple(
                (
                    int(char.characteristic_data[f"x{r}"].replace("0x", "").replace("#x", ""), 16),
                    int(char.characteristic_data[f"y{r}"].replace("0x", "").replace("#x", ""), 16),
                )
                for r in range(rounds + 1)
            )
            trails.add(state_tuple)
        finally:
            if os.path.exists(stp_path):
                os.remove(stp_path)
    return trails


@unittest.skipUnless(
    bool(BITWUZLA_BIN and STP_BIN and os.path.exists(BITWUZLA_BIN) and os.path.exists(STP_BIN)),
    "Bitwuzla and STP binaries required for solver equivalence tests",
)
class TestSimonSpeckEquivalence(unittest.TestCase):

    @classmethod
    def setUpClass(cls):
        cls._orig_stp = solvers.bitwuzla.PATH_STP
        solvers.bitwuzla.PATH_STP = STP_BIN
        cls.solver = BitwuzlaSolver(BITWUZLA_BIN)
        cls.simon_builtin = SimonCipher()
        cls.speck_builtin = SpeckCipher()
        cls.simon_py = load_cipher_from_python(
            os.path.join(REPO_ROOT, "examples", "python_primitives", "simon_ref.py")
        )
        cls.speck_py = load_cipher_from_python(
            os.path.join(REPO_ROOT, "examples", "python_primitives", "speck_ref.py")
        )

    @classmethod
    def tearDownClass(cls):
        solvers.bitwuzla.PATH_STP = cls._orig_stp

    def test_1_simon32_multiround_optimal_weights_and_alternative_python_styles(self):
        """Verifies Simon-32/64 optimal weights for R=1..8 and across alternative Python coding styles."""
        # Custom style B: reversed AND operands + XOR rotation idiom + explicit ~ negation cancels
        def simon_alt_style(x, y):
            rot8 = ((x << 8) ^ (x >> 8)) & 0xFFFF
            rot1 = ((x << 1) ^ (x >> 15)) & 0xFFFF
            rot2 = ((x << 2) | (x >> 14)) & 0xFFFF
            return (rot1 & rot8) ^ rot2 ^ y, x

        simon_alt = build_cipher_from_callable(simon_alt_style, cipher_name="simon_alt")

        expected_weights = {1: 0, 2: 2, 3: 4, 4: 6, 5: 8, 6: 12, 7: 14, 8: 18}
        chars_builtin = {}
        chars_py = {}
        for r in range(1, 9):
            w_builtin, char_builtin = find_min_weight_and_char(self.solver, self.simon_builtin, r, 16)
            w_py, char_py = find_min_weight_and_char(self.solver, self.simon_py, r, 16)
            w_alt, _ = find_min_weight_and_char(self.solver, simon_alt, r, 16)

            self.assertEqual(w_builtin, expected_weights[r], f"Round {r} builtin Simon weight mismatch")
            self.assertEqual(w_py, w_builtin, f"Round {r} simon_py vs builtin Simon weight mismatch")
            self.assertEqual(w_alt, w_builtin, f"Round {r} simon_alt vs builtin Simon weight mismatch")
            chars_builtin[r] = char_builtin
            chars_py[r] = char_py

        # Bidirectional cross-model trail validation for both R=7 (weight 14) and R=8 (weight 18):
        for r, opt_w in ((7, 14), (8, 18)):
            cb = chars_builtin[r]
            cp = chars_py[r]
            fixed_from_builtin = {
                f"{s}{i}": cb.characteristic_data[f"{s}{i}"]
                for i in range(r + 1)
                for s in ("x", "y")
            }
            self.assertTrue(check_sat_at_weight(self.solver, self.simon_py, r, 16, opt_w, fixed_from_builtin))
            self.assertFalse(check_sat_at_weight(self.solver, self.simon_py, r, 16, opt_w - 1, fixed_from_builtin))

            fixed_from_py = {
                f"{s}{i}": cp.characteristic_data[f"{s}{i}"]
                for i in range(r + 1)
                for s in ("x", "y")
            }
            self.assertTrue(check_sat_at_weight(self.solver, self.simon_builtin, r, 16, opt_w, fixed_from_py))
            self.assertFalse(check_sat_at_weight(self.solver, self.simon_builtin, r, 16, opt_w - 1, fixed_from_py))

        # 3. Empirical Monte Carlo check on simon_py optimal 8-round trail
        ver = verify_characteristic_empirically(self.simon_py, chars_py[8], 16)
        self.assertTrue(all(v.passed for v in ver))

    def test_2_speck32_multiround_optimal_weights_across_all_arx_modes(self):
        """Verifies Speck-32/64 optimal weights for R=1..6 across builtin and all 3 ARX modes."""
        expected_weights = {1: 0, 2: 1, 3: 3, 4: 5, 5: 9, 6: 13}
        for r in range(1, 7):
            w_builtin, char_builtin = find_min_weight_and_char(self.solver, self.speck_builtin, r, 16)
            self.assertEqual(w_builtin, expected_weights[r], f"Round {r} builtin Speck weight mismatch")

            for mode in ("lipmaa", "shared_eq", "explicit_carry"):
                w_py, char_py = find_min_weight_and_char(
                    self.solver, self.speck_py, r, 16, extra_params={"arx_mode": mode}
                )
                self.assertEqual(
                    w_py, w_builtin, f"Round {r} speck_py (mode={mode}) vs builtin Speck weight mismatch"
                )

        # Bidirectional cross-model trail validation at R=6 (weight 13):
        fixed_from_builtin = {
            f"{s}{i}": char_builtin.characteristic_data[f"{s}{i}"]
            for i in range(7)
            for s in ("x", "y")
        }
        self.assertTrue(check_sat_at_weight(self.solver, self.speck_py, 6, 16, 13, fixed_from_builtin))
        self.assertFalse(check_sat_at_weight(self.solver, self.speck_py, 6, 16, 12, fixed_from_builtin))

        fixed_from_py = {
            f"{s}{i}": char_py.characteristic_data[f"{s}{i}"]
            for i in range(7)
            for s in ("x", "y")
        }
        self.assertTrue(check_sat_at_weight(self.solver, self.speck_builtin, 6, 16, 13, fixed_from_py))
        self.assertFalse(check_sat_at_weight(self.solver, self.speck_builtin, 6, 16, 12, fixed_from_py))

        # Empirical Monte Carlo check on speck_py 6-round optimal trail
        ver = verify_characteristic_empirically(self.speck_py, char_py, 16)
        self.assertTrue(all(v.passed for v in ver))

    def test_3_speck64_wordsize32_equivalence(self):
        """Verifies Speck-64/128 (wordsize=32, alpha=8, beta=3) equivalence between builtin and Python."""
        def speck64_round(x, y):
            nx = (rotr(x, 8) + y) & 0xFFFFFFFF
            ny = rotl(y, 3) ^ nx
            return nx, ny

        speck64_py = build_cipher_from_callable(speck64_round, cipher_name="speck64_py", default_wordsize=32)
        expected_w32 = {1: 0, 2: 1, 3: 3, 4: 6}
        for r in range(1, 5):
            w_builtin, _ = find_min_weight_and_char(self.solver, self.speck_builtin, r, 32)
            w_py, char_py = find_min_weight_and_char(self.solver, speck64_py, r, 32)
            self.assertEqual(w_builtin, expected_w32[r])
            self.assertEqual(w_py, w_builtin, f"Speck-64 round {r} weight mismatch")

        ver = verify_characteristic_empirically(speck64_py, char_py, 32)
        self.assertTrue(all(v.passed for v in ver))

    def test_4_differential_hull_trail_set_equivalence(self):
        """Verifies that fixing (Delta_in, Delta_out) yields the exact same set of trails in both models."""
        # 1. 4-round Simon-32/64 with fixed endpoints from an optimal 4-round characteristic
        _, simon_char4 = find_min_weight_and_char(self.solver, self.simon_builtin, 4, 16)
        simon_endpoints = {
            "x0": simon_char4.characteristic_data["x0"],
            "y0": simon_char4.characteristic_data["y0"],
            "x4": simon_char4.characteristic_data["x4"],
            "y4": simon_char4.characteristic_data["y4"],
        }
        trails_simon_builtin = enumerate_state_trails_at_weight(
            self.solver, self.simon_builtin, 4, 16, 6, simon_endpoints
        )
        trails_simon_py = enumerate_state_trails_at_weight(
            self.solver, self.simon_py, 4, 16, 6, simon_endpoints
        )
        self.assertGreater(len(trails_simon_builtin), 0)
        self.assertEqual(trails_simon_builtin, trails_simon_py)

        # 2. 4-round Speck-32/64 with fixed endpoints from an optimal 4-round characteristic
        _, speck_char4 = find_min_weight_and_char(self.solver, self.speck_builtin, 4, 16)
        speck_endpoints = {
            "x0": speck_char4.characteristic_data["x0"],
            "y0": speck_char4.characteristic_data["y0"],
            "x4": speck_char4.characteristic_data["x4"],
            "y4": speck_char4.characteristic_data["y4"],
        }
        trails_speck_builtin = enumerate_state_trails_at_weight(
            self.solver, self.speck_builtin, 4, 16, 5, speck_endpoints
        )
        trails_speck_py = enumerate_state_trails_at_weight(
            self.solver, self.speck_py, 4, 16, 5, speck_endpoints
        )
        self.assertGreater(len(trails_speck_builtin), 0)
        self.assertEqual(trails_speck_builtin, trails_speck_py)


if __name__ == "__main__":
    unittest.main()
