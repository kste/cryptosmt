"""Lowers traced CryptoIR round graphs into CryptoSMT AbstractCipher models."""

import importlib.util
import inspect
import linecache
import marshal
import math
import os
import re
import sys
import traceback
import types
from typing import Any, Callable, Dict, List, Optional, Set, Tuple, TextIO

from ciphers.cipher import AbstractCipher
from parser import stpcommands
from parser.stpcommands import getStringLeftRotate as rotl
from .ir import (
    BitAndNode,
    CipherSpecificationError,
    ConstNode,
    CorrelatedRotAndNode,
    InputVarNode,
    IRNode,
    KeyWord,
    ModAddNode,
    RotateLeftNode,
    ShiftLeftNode,
    ShiftRightNode,
    SymWord,
    XorNode,
)

_KEY_PARAM_RE = re.compile(
    r"^(k|rk|key|subkey|round_key|roundkey|keys|subkeys|rc|const|tweak|tk)\d*$",
    re.IGNORECASE,
)


def _format_user_traceback_error(exc: Exception, round_fn: Callable) -> CipherSpecificationError:
    """Extracts the exact user source file, line number, and code line from a tracing exception."""
    tb_frames = traceback.extract_tb(exc.__traceback__)
    this_dir = os.path.dirname(os.path.abspath(__file__))
    user_frame = None
    for frame in reversed(tb_frames):
        if not os.path.abspath(frame.filename).startswith(this_dir):
            user_frame = frame
            break
    if user_frame is not None:
        code_line = (user_frame.line or linecache.getline(user_frame.filename, user_frame.lineno)).strip()
        fname = os.path.basename(user_frame.filename)
        location = f"{fname}:{user_frame.lineno} (in `{user_frame.name}`)"
        snippet = f"\n    >>> {code_line}" if code_line else ""
        msg = f"Invalid cipher description at {location}:{snippet}\n  Reason: {exc}"
    else:
        msg = f"Invalid cipher description in `{getattr(round_fn, '__name__', 'round_function')}`: {exc}"
    return CipherSpecificationError(msg)


class _RoundLoweringCompiler:
    """Compiles a single round's CryptoIR DAG into STP declarations and ASSERT statements."""

    def __init__(
        self,
        round_nr: int,
        wordsize: int,
        state_names: List[str],
        num_nonlinear_hint: int = 1,
        arx_mode: str = "shared_eq",
    ):
        self.round_nr = round_nr
        self.wordsize = wordsize
        self.state_names = state_names
        self.num_nonlinear_hint = num_nonlinear_hint
        self.arx_mode = arx_mode

        self.aux_vars: List[str] = []
        self.weight_vars: List[str] = []
        self.assertions: List[str] = []
        self._memo: Dict[int, str] = {}
        self._fanout: Dict[int, int] = {}
        self._nl_counter = 0
        self._tmp_counter = 0

    def count_fanout(self, roots: List[IRNode]) -> int:
        """Counts node fanout and returns total number of non-linear nodes in the DAG."""
        visited = set()
        nl_count = 0

        def visit(node: IRNode):
            nonlocal nl_count
            nid = node.node_id
            self._fanout[nid] = self._fanout.get(nid, 0) + 1
            if nid in visited:
                return
            visited.add(nid)
            if isinstance(node, (ModAddNode, CorrelatedRotAndNode, BitAndNode)):
                nl_count += 1
            if isinstance(node, (XorNode, ModAddNode, BitAndNode)):
                visit(node.left)
                visit(node.right)
            elif isinstance(node, (RotateLeftNode, ShiftLeftNode, ShiftRightNode)):
                visit(node.operand)
            elif isinstance(node, CorrelatedRotAndNode):
                visit(node.base)

        for r in roots:
            visit(r)
        return nl_count

    def _alloc_weight_var(self) -> str:
        idx = self._nl_counter
        self._nl_counter += 1
        if self.num_nonlinear_hint == 1 and idx == 0 and "w" not in self.state_names:
            w_name = f"w{self.round_nr}"
        else:
            w_name = f"w{idx}_{self.round_nr}"
        self.weight_vars.append(w_name)
        return w_name

    def _alloc_aux_var(self, prefix: str) -> str:
        idx = self._tmp_counter
        self._tmp_counter += 1
        name = f"{prefix}{idx}_r{self.round_nr}"
        self.aux_vars.append(name)
        return name

    def _ensure_atomic(self, expr_str: str, node: IRNode) -> str:
        """Materializes compound expressions into a temporary variable if needed."""
        if isinstance(node, InputVarNode) or expr_str.isidentifier():
            return expr_str
        tmp_var = self._alloc_aux_var("tmp")
        self.assertions.append(f"ASSERT({tmp_var} = {expr_str});\n")
        return tmp_var

    def compile_node(self, node: IRNode) -> str:
        nid = node.node_id
        if nid in self._memo:
            return self._memo[nid]

        w = self.wordsize
        if isinstance(node, InputVarNode):
            res = f"{node.name}{self.round_nr}"
        elif isinstance(node, ConstNode):
            res = f"0bin{node.value & ((1 << w) - 1):0{w}b}"
        elif isinstance(node, XorNode):
            lhs = self.compile_node(node.left)
            rhs = self.compile_node(node.right)
            res = f"BVXOR({lhs}, {rhs})"
        elif isinstance(node, RotateLeftNode):
            sub = self.compile_node(node.operand)
            # Materialize operand if it is a compound expression before rotating
            if not isinstance(node.operand, InputVarNode) and not sub.isidentifier():
                sub = self._ensure_atomic(sub, node.operand)
            res = rotl(sub, node.amount, w)
        elif isinstance(node, ShiftLeftNode):
            sub = self.compile_node(node.operand)
            res = f"((({sub}) << {node.amount})[{w - 1}:0])"
        elif isinstance(node, ShiftRightNode):
            sub = self.compile_node(node.operand)
            res = f"((({sub}) >> {node.amount})[{w - 1}:0])"
        elif isinstance(node, ModAddNode):
            lhs = self._ensure_atomic(self.compile_node(node.left), node.left)
            rhs = self._ensure_atomic(self.compile_node(node.right), node.right)
            out_var = self._alloc_aux_var("add")
            w_var = self._alloc_weight_var()
            msb_mask = "0bin0" + "1" * (w - 1)
            zeros = f"0bin{'0' * w}"
            eq_str = stpcommands.getStringEq(lhs, rhs, out_var)

            if self.arx_mode == "lipmaa":
                # Approach 1: Standard Lipmaa-Moriai formula
                self.assertions.append(f"ASSERT({stpcommands.getStringAdd(lhs, rhs, out_var, w)});\n")
                self.assertions.append(f"ASSERT({w_var} = ((~{eq_str}) & {msb_mask}));\n")
            elif self.arx_mode == "shared_eq":
                # Approach 2: Custom Weight-Sharing + LSB Unit Clause
                self.assertions.append(f"ASSERT({w_var} = ((~{eq_str}) & {msb_mask}));\n")
                self.assertions.append(
                    f"ASSERT(BVXOR({lhs}[0:0], BVXOR({rhs}[0:0], {out_var}[0:0])) = 0bin0);\n"
                )
                not_w_shift = f"(~(({w_var} << 1)[{w - 1}:0]))"
                carry_rel = f"BVXOR({lhs}, BVXOR({rhs}, BVXOR({out_var}, ({rhs} << 1)[{w - 1}:0])))"
                self.assertions.append(f"ASSERT(({not_w_shift} & {carry_rel}) = {zeros});\n")
            elif self.arx_mode == "explicit_carry":
                # Approach 3: Explicit Carry-Difference Vector Model
                carry_var = self._alloc_aux_var("carry")
                self.assertions.append(f"ASSERT({carry_var} = BVXOR({lhs}, BVXOR({rhs}, {out_var})));\n")
                self.assertions.append(f"ASSERT({carry_var}[0:0] = 0bin0);\n")
                self.assertions.append(f"ASSERT({w_var} = ((~{eq_str}) & {msb_mask}));\n")
                not_w_shift = f"(~(({w_var} << 1)[{w - 1}:0]))"
                self.assertions.append(
                    f"ASSERT(({not_w_shift} & BVXOR({carry_var}, ({rhs} << 1)[{w - 1}:0])) = {zeros});\n"
                )
            else:
                raise ValueError(f"Unknown arx_mode: {self.arx_mode}")
            res = out_var
        elif isinstance(node, CorrelatedRotAndNode):
            base_expr = self.compile_node(node.base)
            base_var = self._ensure_atomic(base_expr, node.base)
            out_var = self._alloc_aux_var("andout")
            w_var = self._alloc_weight_var()

            alpha, beta = node.alpha, node.beta
            delta = (alpha - beta) % w
            d = math.gcd(delta, w)
            cycle_len = w // d

            u_rot_a_expr = rotl(base_var, alpha, w)
            u_rot_a = self._ensure_atomic(u_rot_a_expr, node)
            u_rot_b = rotl(base_var, beta, w)
            doublebits = f"({u_rot_b} & ~{u_rot_a} & {rotl(base_var, (2 * alpha - beta) % w, w)})"
            varibits = f"({u_rot_a} | {u_rot_b})"
            valid_expr = (
                f"(({out_var} & ~{varibits}) | "
                f"(BVXOR({out_var}, {rotl(out_var, delta, w)}) & {doublebits}))"
            )
            zeros = f"0bin{'0' * w}"
            self.assertions.append(f"ASSERT({valid_expr} = {zeros});\n")

            # General Kölbl-Leander-Tiessen cycle parity & weight condition for any d = gcd(alpha - beta, w) >= 1
            drop_terms: List[str] = []
            for c in range(d):
                cycle_indices = [(c + k * delta) % w for k in range(cycle_len)]
                cycle_mask_int = sum(1 << i for i in cycle_indices)
                cycle_mask_bin = f"0bin{cycle_mask_int:0{w}b}"
                rep_bit = cycle_indices[0]
                rep_mask_bin = f"0bin{(1 << rep_bit):0{w}b}"

                # XOR parity of out_var over cycle_indices must equal (cycle_len % 2) when cycle is all-ones
                parity_expr = f"{out_var}[{cycle_indices[0]}:{cycle_indices[0]}]"
                for bit_idx in cycle_indices[1:]:
                    parity_expr = f"BVXOR({parity_expr}, {out_var}[{bit_idx}:{bit_idx}])"
                expected_parity = f"0bin{cycle_len % 2}"

                self.assertions.append(
                    f"ASSERT((IF ({u_rot_a} & {cycle_mask_bin}) = {cycle_mask_bin} "
                    f"THEN {parity_expr} ELSE {expected_parity} ENDIF) = {expected_parity});\n"
                )
                drop_terms.append(
                    f"(IF ({u_rot_a} & {cycle_mask_bin}) = {cycle_mask_bin} "
                    f"THEN {rep_mask_bin} ELSE {zeros} ENDIF)"
                )

            drop_mask_expr = drop_terms[0]
            for dt in drop_terms[1:]:
                drop_mask_expr = f"({drop_mask_expr} | {dt})"

            self.assertions.append(
                f"ASSERT({w_var} = (BVXOR({varibits}, {doublebits}) & ~({drop_mask_expr})));\n"
            )
            res = out_var
        elif isinstance(node, BitAndNode):
            lhs = self._ensure_atomic(self.compile_node(node.left), node.left)
            rhs = self._ensure_atomic(self.compile_node(node.right), node.right)
            out_var = self._alloc_aux_var("band")
            w_var = self._alloc_weight_var()
            varibits = f"({lhs} | {rhs})"
            self.assertions.append(f"ASSERT(({out_var} & ~{varibits}) = 0bin{'0' * w});\n")
            self.assertions.append(f"ASSERT({w_var} = {varibits});\n")
            res = out_var
        else:
            raise TypeError(f"Unsupported IR node type: {type(node)}")

        # Common Subexpression Elimination (CSE): materialize linear nodes with fanout > 1
        if self._fanout.get(nid, 1) > 1 and not isinstance(node, InputVarNode) and not res.isidentifier():
            tmp_var = self._alloc_aux_var("cse")
            self.assertions.append(f"ASSERT({tmp_var} = {res});\n")
            res = tmp_var

        self._memo[nid] = res
        return res


class SynthesizedCipher(AbstractCipher):
    """Dynamic CryptoSMT cipher model automatically synthesized from a Python round function."""

    def __init__(
        self,
        cipher_name: str,
        round_fn: Callable,
        state_names: List[str],
        default_wordsize: int = 16,
        accepts_round_nr: bool = False,
        round_param_name: Optional[str] = None,
        arx_mode: str = "shared_eq",
        source_filepath: Optional[str] = None,
        key_names: Optional[List[str]] = None,
    ):
        super().__init__()
        self._cipher_name = cipher_name
        self.round_fn = round_fn
        self.state_names = state_names
        self.key_names = list(key_names) if key_names else []
        self.default_wordsize = default_wordsize
        self.accepts_round_nr = accepts_round_nr
        self.round_param_name = round_param_name
        self.arx_mode = arx_mode
        self.source_filepath = source_filepath
        self._round_statements: Dict[int, List[str]] = {}
        self._max_nl_per_round: int = self._probe_max_nl()

    def _probe_max_nl(self) -> int:
        """Eagerly probes and validates rounds 0..3 to detect invalid cipher specs immediately."""
        probe_rounds = 4 if self.accepts_round_nr else 1
        max_nl = 0
        used_inputs: Set[str] = set()

        for r in range(probe_rounds):
            try:
                roots = self._trace_round(r, self.default_wordsize)
            except CipherSpecificationError as exc:
                raise _format_user_traceback_error(exc, self.round_fn) from exc
            except (ValueError, TypeError, ZeroDivisionError, IndexError, KeyError) as exc:
                raise _format_user_traceback_error(exc, self.round_fn) from exc

            self._validate_round_roots(r, roots, used_inputs)
            comp = _RoundLoweringCompiler(r, self.default_wordsize, self.state_names, arx_mode=self.arx_mode)
            max_nl = max(max_nl, comp.count_fanout(roots))

        unused = [s for s in self.state_names if s not in used_inputs]
        if unused:
            unused_str = ", ".join(f"'{s}'" for s in unused)
            raise CipherSpecificationError(
                f"Invalid cipher description in `{self.round_fn.__name__}`: state parameter(s) {unused_str} "
                f"do not influence any output word (causes trivial weight-0 trails). "
                f"Hint: did you forget to include {unused_str} in the return tuple, or is it a key parameter "
                f"(rename to 'k'/'key'/'rk' or add a default value like `{unused[0]}=0`)?"
            )
        return max_nl

    def _validate_round_roots(self, round_nr: int, roots: List[IRNode], used_inputs: Set[str]) -> None:
        """Validates that round outputs are non-constant, non-collapsing, and tracks used inputs."""
        for idx, root in enumerate(roots):
            sname = self.state_names[idx]
            if isinstance(root, ConstNode):
                raise CipherSpecificationError(
                    f"Invalid cipher description in `{self.round_fn.__name__}` (round {round_nr}): "
                    f"output word {idx} ('{sname}') evaluates to a constant (0x{root.value:x}) "
                    f"and does not depend on any state word."
                )
            for prev_idx in range(idx):
                if roots[prev_idx] is root:
                    prev_name = self.state_names[prev_idx]
                    raise CipherSpecificationError(
                        f"Invalid cipher description in `{self.round_fn.__name__}` (round {round_nr}): "
                        f"output branches {prev_idx} ('{prev_name}') and {idx} ('{sname}') are identical expressions; "
                        f"round function is non-invertible and collapses state."
                    )

        # Collect reachable InputVarNodes
        visited: Set[int] = set()

        def walk(node: IRNode):
            if node.node_id in visited:
                return
            visited.add(node.node_id)
            if isinstance(node, InputVarNode):
                used_inputs.add(node.name)
            elif isinstance(node, (XorNode, ModAddNode, BitAndNode)):
                walk(node.left)
                walk(node.right)
            elif isinstance(node, (RotateLeftNode, ShiftLeftNode, ShiftRightNode)):
                walk(node.operand)
            elif isinstance(node, CorrelatedRotAndNode):
                walk(node.base)

        for r in roots:
            walk(r)

    def describe_model(self) -> str:
        """Returns a human-readable diagnostic summary of the synthesized cipher model."""
        roots = self._trace_round(0, self.default_wordsize)
        visited: Set[int] = set()
        counts = {"ModAdd": 0, "ModSub": 0, "CorrelatedRotAnd": 0, "BitAnd": 0, "Xor": 0, "Rot/Shift": 0}

        def walk(n: IRNode):
            if n.node_id in visited:
                return
            visited.add(n.node_id)
            if isinstance(n, ModAddNode):
                counts["ModSub" if n.is_sub else "ModAdd"] += 1
                walk(n.left)
                walk(n.right)
            elif isinstance(n, CorrelatedRotAndNode):
                counts["CorrelatedRotAnd"] += 1
                walk(n.base)
            elif isinstance(n, BitAndNode):
                counts["BitAnd"] += 1
                walk(n.left)
                walk(n.right)
            elif isinstance(n, XorNode):
                counts["Xor"] += 1
                walk(n.left)
                walk(n.right)
            elif isinstance(n, (RotateLeftNode, ShiftLeftNode, ShiftRightNode)):
                counts["Rot/Shift"] += 1
                walk(n.operand)

        for rt in roots:
            walk(rt)

        ops_summary = ", ".join(f"{v}x {k}" for k, v in counts.items() if v > 0) or "pure permutation"
        keys_str = ", ".join(self.key_names) if self.key_names else "none"
        lines = [
            f"[Transpiler] Synthesized Cipher: '{self.name}' ({len(self.state_names)}x {self.default_wordsize}-bit state words: {self.state_names})",
            f"[Transpiler] Ignored Key/Constant Params: {keys_str} | Round Ops: {ops_summary} ({self._max_nl_per_round} non-linear/round)",
        ]
        if self._max_nl_per_round == 0:
            lines.append(
                "[Transpiler] WARNING: Cipher has 0 non-linear operations per round (purely linear over GF(2)); all trails have weight 0."
            )
        return "\n".join(lines)

    def __getstate__(self) -> Dict[str, Any]:
        state = self.__dict__.copy()
        # Support pickling even when round_fn is a dynamically loaded function or local function
        if self.source_filepath and os.path.isfile(self.source_filepath):
            state["round_fn"] = None
            state["_fn_code_bytes"] = None
        else:
            try:
                import pickle
                pickle.dumps(self.round_fn)
                state["_fn_code_bytes"] = None
            except Exception:
                state["round_fn"] = None
                state["_fn_code_bytes"] = marshal.dumps(self.round_fn.__code__)
                state["_fn_defaults"] = self.round_fn.__defaults__
        return state

    def __setstate__(self, state: Dict[str, Any]) -> None:
        fn_code_bytes = state.pop("_fn_code_bytes", None)
        fn_defaults = state.pop("_fn_defaults", None)
        self.__dict__.update(state)
        if self.round_fn is None:
            if self.source_filepath and os.path.isfile(self.source_filepath):
                reloaded = load_cipher_from_python(self.source_filepath)
                self.round_fn = reloaded.round_fn
            elif fn_code_bytes is not None:
                code_obj = marshal.loads(fn_code_bytes)
                from . import ir as _ir_mod
                fn_globals = {"__builtins__": __builtins__, "rotl": _ir_mod.rotl, "rotr": _ir_mod.rotr}
                self.round_fn = types.FunctionType(code_obj, fn_globals, self._cipher_name, fn_defaults)

    @property
    def name(self) -> str:
        return self._cipher_name

    def validate_parameters(self, parameters: Dict[str, Any]) -> None:
        if "wordsize" not in parameters or not parameters["wordsize"]:
            parameters["wordsize"] = self.default_wordsize
        # Weight variables in SynthesizedCipher already mask the MSB or exact cycle bits
        parameters["ignore_msbs"] = 0

    def getFormatString(self) -> List[str]:
        if self._max_nl_per_round == 1 and "w" not in self.state_names:
            return list(self.state_names) + ["w"]
        elif self._max_nl_per_round >= 1:
            return list(self.state_names) + [f"w{i}_" for i in range(self._max_nl_per_round)]
        return list(self.state_names)

    def _trace_round(self, round_nr: int, wordsize: int) -> List[IRNode]:
        sym_inputs = [SymWord.input_var(name, wordsize) for name in self.state_names]
        kwargs: Dict[str, Any] = {}
        if self.accepts_round_nr and self.round_param_name:
            kwargs[self.round_param_name] = round_nr
        for kname in getattr(self, "key_names", ()):
            kwargs[kname] = KeyWord(kname)
        raw_outputs = self.round_fn(*sym_inputs, **kwargs)
        if raw_outputs is None:
            raise ValueError("Round function returned None; expected state word tuple")
        if isinstance(raw_outputs, (SymWord, KeyWord, int)):
            raw_outputs = (raw_outputs,)
        if len(raw_outputs) != len(self.state_names):
            raise ValueError(
                f"Round function returned {len(raw_outputs)} outputs, "
                f"expected {len(self.state_names)} ({self.state_names})"
            )
        return [out.node if isinstance(out, SymWord) else ConstNode(int(out), wordsize) for out in raw_outputs]

    def setup_variables(self, stp_file: TextIO, parameters: Dict[str, Any]):
        wordsize = parameters.get("wordsize") or self.default_wordsize
        parameters["wordsize"] = wordsize
        parameters["ignore_msbs"] = 0
        rounds = parameters["rounds"]

        # 1. Declare round state variables
        self._state_vectors = {}
        for sname in self.state_names:
            self._state_vectors[sname] = self.declare_variable_vector(
                stp_file, sname, rounds, wordsize, is_state=True
            )

        # 2. Pass 1: Trace all rounds and compute global max_nl across the entire cipher
        arx_mode = parameters.get("arx_mode", self.arx_mode)
        round_roots: List[List[IRNode]] = []
        max_nl = 0
        for r in range(rounds):
            roots = self._trace_round(r, wordsize)
            round_roots.append(roots)
            probe_comp = _RoundLoweringCompiler(r, wordsize, self.state_names, arx_mode=arx_mode)
            nl_count = probe_comp.count_fanout(roots)
            max_nl = max(max_nl, nl_count)

        self._max_nl_per_round = max_nl

        # 3. Pass 2: Compile each round using the uniform global max_nl hint
        self._round_statements = {}
        all_aux_vars: List[str] = []
        all_weight_vars: List[str] = []

        for r in range(rounds):
            roots = round_roots[r]
            compiler = _RoundLoweringCompiler(
                r, wordsize, self.state_names, num_nonlinear_hint=max_nl, arx_mode=arx_mode
            )
            compiler.count_fanout(roots)

            for idx, sname in enumerate(self.state_names):
                out_expr = compiler.compile_node(roots[idx])
                next_state_var = self._state_vectors[sname][r + 1]
                compiler.assertions.append(f"ASSERT({next_state_var} = {out_expr});\n")

            all_aux_vars.extend(compiler.aux_vars)
            all_weight_vars.extend(compiler.weight_vars)
            self._round_statements[r] = compiler.assertions

        if all_aux_vars:
            stpcommands.setupVariables(stp_file, all_aux_vars, wordsize)
        if all_weight_vars:
            stpcommands.setupVariables(stp_file, all_weight_vars, wordsize)
            self.weight_variables.extend(all_weight_vars)
        else:
            # Purely linear cipher (max_nl == 0): declare a constant-0 weight variable so weight = 0
            dummy_w = "w0_linear"
            stpcommands.setupVariables(stp_file, [dummy_w], wordsize)
            stp_file.write(f"ASSERT({dummy_w} = 0bin{'0' * wordsize});\n")
            self.weight_variables.append(dummy_w)

    def apply_round_constraints(self, stp_file: TextIO, round_nr: int, parameters: Dict[str, Any]):
        for stmt in self._round_statements.get(round_nr, []):
            stp_file.write(stmt)

    def apply_iterative_constraints(self, stp_file: TextIO, parameters: Dict[str, Any]):
        rounds = parameters["rounds"]
        for sname in self.state_names:
            vec = self._state_vectors[sname]
            stpcommands.assertVariableValue(stp_file, vec[0], vec[rounds])

    def export_cipher_module(self, target_path: str, source_module_path: str) -> None:
        """Exports a standalone AbstractCipher Python module wrapping the reference file."""
        abs_source = os.path.abspath(source_module_path)
        exported_name = os.path.splitext(os.path.basename(target_path))[0]
        class_name = "".join(part.capitalize() for part in exported_name.split("_")) + "AutoCipher"
        code = f'''"""Auto-generated CryptoSMT cipher model from {os.path.basename(abs_source)}."""

from transpiler import load_cipher_from_python

_BASE = load_cipher_from_python({abs_source!r})


class {class_name}(type(_BASE)):
    def __init__(self):
        super().__init__(
            cipher_name={exported_name!r},
            round_fn=_BASE.round_fn,
            state_names=_BASE.state_names,
            default_wordsize=_BASE.default_wordsize,
            accepts_round_nr=_BASE.accepts_round_nr,
            round_param_name=_BASE.round_param_name,
            source_filepath={abs_source!r},
            key_names=_BASE.key_names,
        )
'''
        with open(target_path, "w") as f:
            f.write(code)


def build_cipher_from_callable(
    round_fn: Callable,
    cipher_name: Optional[str] = None,
    default_wordsize: int = 16,
    source_filepath: Optional[str] = None,
) -> SynthesizedCipher:
    """Inspects a Python round function and returns a SynthesizedCipher instance."""
    sig = inspect.signature(round_fn)
    state_names: List[str] = []
    key_names: List[str] = []
    accepts_round_nr = False
    round_param_name = None

    for pname, param in sig.parameters.items():
        if pname in ("round_nr", "round_idx", "r", "round"):
            accepts_round_nr = True
            round_param_name = pname
        elif param.default is not inspect.Parameter.empty or _KEY_PARAM_RE.match(pname):
            # Optional or explicitly named key/subkey/constant parameter (e.g. k, rk, key, k0, k=0)
            key_names.append(pname)
        else:
            state_names.append(pname)

    if not state_names:
        raise ValueError(f"Round function {round_fn.__name__} must accept at least one state argument")

    name = cipher_name or round_fn.__name__.replace("_round", "").replace("round_", "")
    return SynthesizedCipher(
        cipher_name=name,
        round_fn=round_fn,
        state_names=state_names,
        default_wordsize=default_wordsize,
        accepts_round_nr=accepts_round_nr,
        round_param_name=round_param_name,
        source_filepath=source_filepath,
        key_names=key_names,
    )


def load_cipher_from_python(filepath: str) -> SynthesizedCipher:
    """Loads a Python file containing a `round_function` (or `cipher_round`) and returns a SynthesizedCipher."""
    abs_path = os.path.abspath(filepath)
    if not os.path.isfile(abs_path):
        raise FileNotFoundError(f"Python primitive file not found: {filepath}")

    mod_name = f"_cryptosmt_synth_{os.path.splitext(os.path.basename(abs_path))[0]}"
    spec = importlib.util.spec_from_file_location(mod_name, abs_path)
    if spec is None or spec.loader is None:
        raise ImportError(f"Could not load module specification from {abs_path}")

    module = importlib.util.module_from_spec(spec)
    sys.modules[mod_name] = module
    spec.loader.exec_module(module)

    # Look for round function
    round_fn = None
    for candidate in ("round_function", "cipher_round", "round_fn", "step"):
        if hasattr(module, candidate) and callable(getattr(module, candidate)):
            round_fn = getattr(module, candidate)
            break

    if round_fn is None:
        # Fallback: first user-defined function in the module that isn't rotl/rotr
        for attr_name in dir(module):
            if attr_name.startswith("_") or attr_name in ("rotl", "rotr"):
                continue
            attr = getattr(module, attr_name)
            if inspect.isfunction(attr) and attr.__module__ == module.__name__:
                round_fn = attr
                break

    if round_fn is None:
        raise ValueError(
            f"No round function found in {filepath}. Define `def round_function(...):`."
        )

    cipher_name = getattr(module, "CIPHER_NAME", os.path.splitext(os.path.basename(abs_path))[0])
    default_wordsize = getattr(module, "WORDSIZE", 16)
    return build_cipher_from_callable(
        round_fn,
        cipher_name=cipher_name,
        default_wordsize=default_wordsize,
        source_filepath=abs_path,
    )
