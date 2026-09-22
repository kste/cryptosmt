"""Unit tests for the Python-to-CryptoSMT transpiler, variable dependencies, and generic designs."""

import os
import sys
import tempfile
import unittest

sys.path.insert(0, os.path.abspath(os.path.join(os.path.dirname(__file__), "..", "..")))

from transpiler import (
    SymWord,
    build_cipher_from_callable,
    load_cipher_from_python,
    rotl,
    rotr,
    verify_round_transition_empirically,
)
from transpiler.ir import (
    BitAndNode,
    ConstNode,
    CorrelatedRotAndNode,
    InputVarNode,
    ModAddNode,
    RotateLeftNode,
    ShiftLeftNode,
    XorNode,
)


class TestTranspilerIRAndDependencies(unittest.TestCase):
    def test_pure_python_rotation_recognition(self):
        x = SymWord.input_var("x", 16)
        rotl_7 = ((x << 7) | (x >> 9)) & 0xFFFF
        self.assertIsInstance(rotl_7.node, RotateLeftNode)
        self.assertEqual(rotl_7.node.amount, 7)
        self.assertIs(rotl_7.node.operand, x.node)

        rotr_7 = ((x >> 7) | (x << 9)) & 0xFFFF
        self.assertIsInstance(rotr_7.node, RotateLeftNode)
        self.assertEqual(rotr_7.node.amount, 9)

    def test_constant_folding_and_inversion(self):
        x = SymWord.input_var("x", 16)
        self.assertIs((x ^ 0xBEEF).node, x.node)
        self.assertIs((0x1234 ^ x).node, x.node)
        self.assertIs((~x).node, x.node)

    def test_gf2_linear_cancellation_and_commutativity(self):
        x = SymWord.input_var("x", 16)
        y = SymWord.input_var("y", 16)
        z = SymWord.input_var("z", 16)

        # (x ^ y) ^ x == y
        self.assertIs(((x ^ y) ^ x).node, y.node)
        # (x ^ y ^ z) ^ (z ^ x) == y
        self.assertIs(((x ^ y ^ z) ^ (z ^ x)).node, y.node)
        # Commutativity: (x ^ y) is the exact same canonical IRNode as (y ^ x)
        self.assertIs((x ^ y).node, (y ^ x).node)
        # Distributivity of rotation over XOR: rotl(x ^ y, 5) ^ rotl(x, 5) == rotl(y, 5)
        self.assertIs((rotl(x ^ y, 5) ^ rotl(x, 5)).node, rotl(y, 5).node)

    def test_distributed_linear_correlated_and_dependency(self):
        x = SymWord.input_var("x", 16)
        y = SymWord.input_var("y", 16)

        # Distributed form: (rotl(x, 8) ^ rotl(y, 8)) & (rotl(x, 1) ^ rotl(y, 1))
        lhs = rotl(x, 8) ^ rotl(y, 8)
        rhs = rotl(x, 1) ^ rotl(y, 1)
        corr = lhs & rhs
        self.assertIsInstance(corr.node, CorrelatedRotAndNode)
        self.assertEqual(corr.node.alpha, 8)
        self.assertEqual(corr.node.beta, 1)
        self.assertIs(corr.node.base, (x ^ y).node)

        # After linear cancellation: u = (x ^ y) ^ y == x -> rotl(u, 8) & rotl(x, 1)
        u = (x ^ y) ^ y
        corr2 = rotl(u, 8) & rotl(x, 1)
        self.assertIsInstance(corr2.node, CorrelatedRotAndNode)
        self.assertIs(corr2.node.base, x.node)

        # Shifted offsets: (rotl(x, 10) ^ rotl(y, 5)) & (rotl(x, 3) ^ rotl(y, 14))
        # Both x and y differ by +7 mod 16 between lhs and rhs
        lhs_off = rotl(x, 10) ^ rotl(y, 5)
        rhs_off = rotl(x, 3) ^ rotl(y, 14)
        corr3 = lhs_off & rhs_off
        self.assertIsInstance(corr3.node, CorrelatedRotAndNode)
        self.assertEqual((corr3.node.alpha - corr3.node.beta) % 16, 7)

    def test_arithmetic_and_bitwise_self_dependencies(self):
        x = SymWord.input_var("x", 16)
        y = SymWord.input_var("y", 16)

        # x + x == x << 1 (deterministic linear shift, weight 0)
        dbl = (x + x) & 0xFFFF
        self.assertIsInstance(dbl.node, ShiftLeftNode)
        self.assertEqual(dbl.node.amount, 1)
        self.assertIs(dbl.node.operand, x.node)

        # x - x == 0
        zero = (x - x) & 0xFFFF
        self.assertIsInstance(zero.node, ConstNode)
        self.assertEqual(zero.node.value, 0)

        # (x + y) - y == x and (x - y) + y == x
        self.assertIs((((x + y) & 0xFFFF) - y).node, x.node)
        self.assertIs((((x - y) & 0xFFFF) + y).node, x.node)

        # Idempotence: x & x == x, x | x == x
        self.assertIs((x & x).node, x.node)
        self.assertIs((x | x).node, x.node)

    def test_structural_hash_consing_for_duplicate_helper_calls(self):
        # User defines a helper function and calls it twice in the same round without caching
        def f_add(a, b):
            return (a + b) & 0xFFFF

        def f_nl(a):
            return rotl(a, 8) & rotl(a, 1)

        def duplicate_helper_round(x, y, z):
            # f_add(x, y) and f_add(y, x) compute the exact same sum
            # f_nl(x) is called in two branches
            out_x = f_add(x, y) ^ f_nl(x)
            out_y = f_add(y, x) ^ z
            out_z = f_nl(x) ^ y
            return out_x, out_y, out_z

        cipher = build_cipher_from_callable(duplicate_helper_round, cipher_name="dup_test")
        with tempfile.NamedTemporaryFile(suffix=".stp", delete=False) as tf:
            stp_path = tf.name
        try:
            cipher.createSTP(stp_path, {"rounds": 1, "wordsize": 16, "sweight": 2})
            # Because f_add(x,y)==f_add(y,x) and f_nl(x)==f_nl(x) are hash-consed,
            # only 2 non-linear weight variables (1 for f_add, 1 for f_nl) should exist for the round, NOT 4!
            self.assertEqual(len(cipher.weight_variables), 2)
        finally:
            if os.path.exists(stp_path):
                os.remove(stp_path)

    def test_generic_feistel_and_lai_massey_custom_designs(self):
        # 1. Generic Lai-Massey ARX primitive with shared non-linear core t
        def lai_massey_round(x, y):
            diff = (x - y) & 0xFFFF
            t = (diff + rotl(x ^ y, 5)) & 0xFFFF
            return rotl(x ^ t, 3), y ^ t

        lm_cipher = build_cipher_from_callable(lai_massey_round, cipher_name="lai_massey")
        with tempfile.NamedTemporaryFile(suffix=".stp", delete=False) as tf:
            stp_path = tf.name
        try:
            lm_cipher.createSTP(stp_path, {"rounds": 2, "wordsize": 16, "sweight": 4})
            # 2 non-linear ops per round (diff and t) * 2 rounds = 4 weight variables
            self.assertEqual(len(lm_cipher.weight_variables), 4)
        finally:
            if os.path.exists(stp_path):
                os.remove(stp_path)

        # Verify zero-difference propagation empirically on the Lai-Massey design
        ver = verify_round_transition_empirically(
            lm_cipher,
            round_nr=0,
            input_diff=(0, 0),
            output_diff=(0, 0),
            claimed_weight=0,
            wordsize=16,
            min_samples=512,
        )
        self.assertTrue(ver.passed)

        # 2. Generic 4-branch Type-II Generalized Feistel Network (GFN)
        def gfn4_round(b0, b1, b2, b3, round_nr=0):
            f0 = ((rotl(b0, 7) + b1) & 0xFFFF) ^ round_nr
            f1 = (rotl(b2, 8) & rotl(b2, 1)) ^ b3
            return b1, f0, b3, f1

        gfn_cipher = build_cipher_from_callable(gfn4_round, cipher_name="gfn4")
        with tempfile.NamedTemporaryFile(suffix=".stp", delete=False) as tf:
            stp_path = tf.name
        try:
            gfn_cipher.createSTP(stp_path, {"rounds": 3, "wordsize": 16, "sweight": 3})
            # 1 ModAdd + 1 CorrelatedRotAnd per round * 3 rounds = 6 weight variables
            self.assertEqual(len(gfn_cipher.weight_variables), 6)
        finally:
            if os.path.exists(stp_path):
                os.remove(stp_path)

    def test_stp_generation_and_arx_modes(self):
        repo_root = os.path.abspath(os.path.join(os.path.dirname(__file__), "..", ".."))
        primitives = [
            ("simon_ref.py", 16, 4),
            ("speck_ref.py", 16, 4),
            ("cham_ref.py", 16, 4),
            ("alzette_ref.py", 32, 4),
            ("chaskey_ref.py", 16, 16),
            ("custom_arx_sub_3way.py", 16, 12),
        ]
        for fname, expected_ws, expected_w_vars in primitives:
            path = os.path.join(repo_root, "examples", "python_primitives", fname)
            cipher = load_cipher_from_python(path)
            self.assertEqual(cipher.default_wordsize, expected_ws)

            for arx_mode in ("lipmaa", "shared_eq", "explicit_carry"):
                with tempfile.NamedTemporaryFile(suffix=".stp", delete=False) as tf:
                    stp_path = tf.name
                try:
                    params = {
                        "rounds": 4,
                        "wordsize": expected_ws,
                        "sweight": 5,
                        "arx_mode": arx_mode,
                    }
                    cipher.createSTP(stp_path, params)
                    with open(stp_path, "r") as f:
                        content = f.read()
                    self.assertIn("QUERY(FALSE);", content)
                    self.assertIn("ASSERT(weight =", content)
                    self.assertEqual(len(cipher.weight_variables), expected_w_vars)
                finally:
                    if os.path.exists(stp_path):
                        os.remove(stp_path)

    def test_reviewer1_shift_distributivity_and_associative_rotations(self):
        x = SymWord.input_var("x", 16)
        y = SymWord.input_var("y", 16)
        z = SymWord.input_var("z", 16)

        # 1. Shift distributivity over XOR: ((x ^ y) << 3) ^ (x << 3) == (y << 3)
        expr_shl = ((x ^ y) << 3) ^ (x << 3)
        expected_shl = y << 3
        self.assertIs(expr_shl.node, expected_shl.node)

        expr_shr = ((x ^ y) >> 4) ^ (y >> 4)
        expected_shr = x >> 4
        self.assertIs(expr_shr.node, expected_shr.node)

        # 2. Associative multi-term XOR coalescing of complementary shifts:
        #    z ^ (x << 5) ^ (x >> 11) == z ^ rotl(x, 5)
        assoc_rot = z ^ (x << 5) ^ (x >> 11)
        expected_assoc = z ^ rotl(x, 5)
        self.assertIs(assoc_rot.node, expected_assoc.node)

        #    And cancelling against rotl(x, 5): (z ^ (x << 5) ^ (x >> 11)) ^ rotl(x, 5) == z
        cancelled = assoc_rot ^ rotl(x, 5)
        self.assertIs(cancelled.node, z.node)

        # 3. Additional additive/subtractive identities:
        #    x - (x - y) == y
        self.assertIs((x - (x - y)).node, y.node)
        #    (x + y) + (x - y) == x << 1
        self.assertIs(((x + y) + (x - y)).node, (x << 1).node)
        #    (x + z) - (y + z) == x - y
        self.assertIs(((x + z) - (y + z)).node, (x - y).node)

    def test_reviewer1_non_coprime_correlated_rot_and_and_operand_order(self):
        # 1. Operand order (alpha < beta vs alpha > beta) with linear combinations
        x = SymWord.input_var("x", 16)
        y = SymWord.input_var("y", 16)
        u = x ^ rotl(y, 3)
        e1 = rotl(u, 1) & rotl(u, 8)
        e2 = rotl(u, 8) & rotl(u, 1)
        self.assertIsInstance(e1.node, CorrelatedRotAndNode)
        self.assertIs(e1.node, e2.node)
        # Verify base is exactly u (unrotated)
        self.assertIs(e1.node.base, u.node)

        # 2. Non-coprime rotation offset: alpha=8, beta=2 on 16-bit word -> delta=6, gcd(6, 16)=2
        def non_coprime_and_round(a, b):
            return (rotl(a, 8) & rotl(a, 2)) ^ b, a

        cipher = build_cipher_from_callable(non_coprime_and_round, cipher_name="non_coprime_and")
        with tempfile.NamedTemporaryFile(suffix=".stp", delete=False) as tf:
            stp_path = tf.name
        try:
            cipher.createSTP(stp_path, {"rounds": 1, "wordsize": 16, "sweight": 7})
            with open(stp_path, "r") as f:
                content = f.read()
            # Should contain cycle masks 0x5555 (0101010101010101) and 0xAAAA (1010101010101010)
            self.assertIn("0bin0101010101010101", content)
            self.assertIn("0bin1010101010101010", content)
        finally:
            if os.path.exists(stp_path):
                os.remove(stp_path)

        # Verify empirically that input_diff=(0x5555, 0) -> output_diff=(0x0000, 0x5555) has weight 7 (not 8!)
        ver = verify_round_transition_empirically(
            cipher,
            round_nr=0,
            input_diff=(0x5555, 0x0000),
            output_diff=(0x0000, 0x5555),
            claimed_weight=7,
            wordsize=16,
            min_samples=1 << 14,
        )
        self.assertTrue(ver.passed, f"Expected weight 7 for half-word cycle 0x5555, got {ver.empirical_weight}")

    def test_reviewer2_state_var_named_w_and_varying_nonlinear_counts(self):
        from cryptanalysis.diffchars import DifferentialCharacteristic

        # 1. State variable named 'w' (e.g. x, y, z, w) must not collide with weight variable w0
        def xyzw_round(x, y, z, w):
            return (x + y) & 0xFFFF, z, w, x ^ w

        cipher_w = build_cipher_from_callable(xyzw_round, cipher_name="xyzw_custom")
        self.assertEqual(cipher_w.getFormatString(), ["x", "y", "z", "w", "w0_"])
        fake_data = {
            "x0": "0x0001", "y0": "0x0000", "z0": "0x0000", "w0": "0x1234", "w0_0": "0x0001",
            "x1": "0x0001", "y1": "0x0000", "z1": "0x1234", "w1": "0x1235",
        }
        dc = DifferentialCharacteristic(fake_data, cipher_w, rounds=1, weight="0x0001")
        table_rows = dc.getData()
        # Column 3 ('w') must be preserved as hex state "0x1234", while column 4 ('w0_') is formatted as weight "-1"
        self.assertEqual(table_rows[0][3], "0x1234")
        self.assertEqual(table_rows[0][4], "-1")

        # 2. Varying non-linear counts across even/odd rounds + purely linear cipher
        def varying_round(a, b, round_nr=0):
            if round_nr % 2 == 0:
                return (a + b) & 0xFFFF, rotl(b, 3)
            else:
                t = (a + b) & 0xFFFF
                return (t + rotl(b, 5)) & 0xFFFF, t ^ a

        var_cipher = build_cipher_from_callable(varying_round, cipher_name="varying_nl")
        self.assertEqual(var_cipher.getFormatString(), ["a", "b", "w0_", "w1_"])
        with tempfile.NamedTemporaryFile(suffix=".stp", delete=False) as tf:
            stp_path = tf.name
        try:
            var_cipher.createSTP(stp_path, {"rounds": 2, "wordsize": 16, "sweight": 3})
            self.assertIn("w0_0", var_cipher.weight_variables)
            self.assertIn("w0_1", var_cipher.weight_variables)
            self.assertIn("w1_1", var_cipher.weight_variables)
        finally:
            if os.path.exists(stp_path):
                os.remove(stp_path)

        # 3. Purely linear cipher (max_nl == 0)
        def linear_round(a, b):
            return rotl(a, 5) ^ b, rotl(b, 3) ^ a

        lin_cipher = build_cipher_from_callable(linear_round, cipher_name="pure_linear")
        with tempfile.NamedTemporaryFile(suffix=".stp", delete=False) as tf:
            stp_path = tf.name
        try:
            lin_cipher.createSTP(stp_path, {"rounds": 2, "wordsize": 16, "sweight": 0})
            self.assertEqual(len(lin_cipher.weight_variables), 1)
        finally:
            if os.path.exists(stp_path):
                os.remove(stp_path)

    def test_reviewer2_multiprocessing_pickling(self):
        import pickle

        repo_root = os.path.abspath(os.path.join(os.path.dirname(__file__), "..", ".."))
        speck_path = os.path.join(repo_root, "examples", "python_primitives", "speck_ref.py")
        cipher_file = load_cipher_from_python(speck_path)
        unpickled_file = pickle.loads(pickle.dumps(cipher_file))
        self.assertEqual(unpickled_file.name, cipher_file.name)
        self.assertEqual(unpickled_file.getFormatString(), cipher_file.getFormatString())

        def local_custom_round(x, y):
            return (rotl(x, 7) + y) & 0xFFFF, rotl(y, 2) ^ x

        cipher_local = build_cipher_from_callable(local_custom_round, cipher_name="local_pickled")
        unpickled_local = pickle.loads(pickle.dumps(cipher_local))
        self.assertEqual(unpickled_local.getFormatString(), ["x", "y", "w"])
        out_orig = cipher_local.round_fn(0x1234, 0x5678)
        out_unpickled = unpickled_local.round_fn(0x1234, 0x5678)
        self.assertEqual(out_orig, out_unpickled)

    def test_key_additions_and_subkeys_ignored(self):
        # 1. Keyed Speck/LEA-style ARX with positional key params (no defaults), subscripted rk[i],
        #    XOR key additions, modular key additions (+ k0, - k1), and constant additions (+ 0x9E37)
        def unkeyed_speck(x, y):
            nx = (rotr(x, 7) + y) & 0xFFFF
            ny = rotl(y, 2) ^ nx
            return nx, ny

        def keyed_speck(x, y, k0, k1, rk, round_nr=0):
            # Inline key schedule expression on k0, k1, and subscripted rk
            subk = rotl(k0, 3) ^ rk[round_nr] ^ k1
            x_whiten = ((x + k0) - k1) & 0xFFFF
            y_whiten = (y ^ k1 ^ rk[0]) & 0xFFFF
            nx = ((rotr(x_whiten, 7) + y_whiten) + subk) & 0xFFFF
            ny = (rotl(y_whiten, 2) ^ nx) ^ rk[1]
            return nx, ny

        def const_keyed_speck(x, y, k=0):
            nx = (((rotr(x, 7) + y) & 0xFFFF) + 0x9E37 - 0x1234 + k) & 0xFFFF
            ny = (rotl(y, 2) ^ nx) ^ 0xABCD
            return nx, ny

        c_unkeyed = build_cipher_from_callable(unkeyed_speck, cipher_name="unkeyed")
        c_keyed = build_cipher_from_callable(keyed_speck, cipher_name="keyed")
        c_const = build_cipher_from_callable(const_keyed_speck, cipher_name="const_keyed")

        self.assertEqual(c_keyed.state_names, ["x", "y"])
        self.assertEqual(c_keyed.key_names, ["k0", "k1", "rk"])

        # Traced IR roots for both keyed_speck and const_keyed_speck must be identical to unkeyed_speck!
        roots_unkeyed = c_unkeyed._trace_round(0, 16)
        roots_keyed = c_keyed._trace_round(0, 16)
        roots_const = c_const._trace_round(0, 16)
        self.assertIs(roots_keyed[0], roots_unkeyed[0])
        self.assertIs(roots_keyed[1], roots_unkeyed[1])
        self.assertIs(roots_const[0], roots_unkeyed[0])
        self.assertIs(roots_const[1], roots_unkeyed[1])

        # Empirical verifier must also run cleanly with key parameters ignored
        ver = verify_round_transition_empirically(
            c_keyed,
            round_nr=0,
            input_diff=(0x0040, 0x0000),
            output_diff=(0x8000, 0x8000),
            claimed_weight=0,
            wordsize=16,
            min_samples=512,
        )
        self.assertTrue(ver.passed)

    def test_invalid_cipher_descriptions_rejected(self):
        # 1. Non-existent file
        with self.assertRaises(FileNotFoundError):
            load_cipher_from_python("/tmp/nonexistent_cryptosmt_primitive_12345.py")

        # 2. Python file with no round function
        with tempfile.NamedTemporaryFile("w", suffix=".py", delete=False) as tf:
            tf.write("WORDSIZE = 16\nCIPHER_NAME = 'empty'\n")
            empty_path = tf.name
        try:
            with self.assertRaises(ValueError):
                load_cipher_from_python(empty_path)
        finally:
            if os.path.exists(empty_path):
                os.remove(empty_path)

        # 3. Round function with zero state arguments (only key/round_nr)
        def no_state_round(k=0, round_nr=0):
            return k

        with self.assertRaises(ValueError):
            build_cipher_from_callable(no_state_round)

        # 4. Mismatched output count (2 inputs, 1 output or 3 outputs or None)
        def bad_arity_1(x, y):
            return x ^ y

        def bad_arity_3(x, y):
            return x, y, x ^ y

        def bad_arity_none(x, y):
            return None

        for fn in (bad_arity_1, bad_arity_3, bad_arity_none):
            with self.assertRaises(ValueError):
                build_cipher_from_callable(fn)

        # 5. Invalid bitwise OR not forming a rotation
        def bad_or_round(x, y):
            return (x | y), x

        with self.assertRaises(ValueError):
            build_cipher_from_callable(bad_or_round)

        # 6. Data-dependent shift / rotation amount (shifting/rotating by state variable y)
        def bad_var_shift(x, y):
            return (x << y), y

        def bad_var_rot(x, y):
            return rotl(x, y), y

        for fn in (bad_var_shift, bad_var_rot):
            with self.assertRaises(TypeError):
                build_cipher_from_callable(fn)

        # 7. Unsupported multiplication / division / partial bitmask / wrong modulus
        def bad_mul(x, y):
            return (x * y) & 0xFFFF, y

        def bad_div(x, y):
            return (x // 3), y

        def bad_partial_mask(x, y):
            return (x & 0x00FF), y

        def bad_modulus(x, y):
            return (x % 255), y

        for fn in (bad_mul, bad_div, bad_partial_mask, bad_modulus):
            with self.assertRaises(ValueError):
                build_cipher_from_callable(fn)

        # 8. Data-dependent control flow (`if x:`), comparison (`if x > y:`), or S-box indexing (`S[x]`)
        def bad_branch(x, y):
            if x:
                return x + y, y
            return x ^ y, x

        def bad_compare(x, y):
            return (x + y if x > y else x ^ y), x

        def bad_sbox_lookup(x, y):
            sbox = list(range(16))
            return sbox[x], y

        for fn in (bad_branch, bad_compare, bad_sbox_lookup):
            with self.assertRaises(TypeError):
                build_cipher_from_callable(fn)

        # 9. Structural DAG checks: unused state parameter, constant/zero output, duplicate collapsing outputs
        def unused_state_param(x, y, z):
            # 'z' is completely ignored
            return (x + y) & 0xFFFF, x ^ y, x

        with self.assertRaises(ValueError) as ctx_unused:
            build_cipher_from_callable(unused_state_param)
        self.assertIn("'z'", str(ctx_unused.exception))
        self.assertIn("do not influence any output word", str(ctx_unused.exception))

        def zero_output_branch(x, y):
            # Second output branch cancels to constant 0
            return (x + y) & 0xFFFF, (x ^ y) ^ (y ^ x)

        with self.assertRaises(ValueError) as ctx_zero:
            build_cipher_from_callable(zero_output_branch)
        self.assertIn("evaluates to a constant", str(ctx_zero.exception))

        def duplicate_collapsing_branches(x, y):
            t = (x + y) & 0xFFFF
            return t, t

        with self.assertRaises(ValueError) as ctx_dup:
            build_cipher_from_callable(duplicate_collapsing_branches)
        self.assertIn("identical expressions", str(ctx_dup.exception))

        # 10. Actionable hints for wrong-wordsize rotation and wrong-wordsize mask + source line snippet
        def wrong_wordsize_rot(x, y):
            return ((x << 5) | (x >> (16 - 5))) ^ y, x

        with self.assertRaises(ValueError) as ctx_rot:
            build_cipher_from_callable(wrong_wordsize_rot, default_wordsize=32)
        self.assertIn("shift amounts sum to 16, but cipher wordsize is 32", str(ctx_rot.exception))
        self.assertIn(">>>", str(ctx_rot.exception))

        def wrong_wordsize_mask(x, y):
            return ((x + y) & 0xFFFF), x

        with self.assertRaises(ValueError) as ctx_mask:
            build_cipher_from_callable(wrong_wordsize_mask, default_wordsize=32)
        self.assertIn("16-bit mask, but cipher wordsize is 32", str(ctx_mask.exception))

        # 11. Verify describe_model() banner output
        repo_root = os.path.abspath(os.path.join(os.path.dirname(__file__), "..", ".."))
        simon_cipher = load_cipher_from_python(
            os.path.join(repo_root, "examples", "python_primitives", "simon_ref.py")
        )
        summary = simon_cipher.describe_model()
        self.assertIn("simon_py", summary)
        self.assertIn("1x CorrelatedRotAnd", summary)
        self.assertIn("Ignored Key/Constant Params: k", summary)


if __name__ == "__main__":
    unittest.main()
