"""Symbolic Bit-Vector Tracer and Intermediate Representation (CryptoIR) for CryptoSMT.

Includes:
- Canonical GF(2) linear basis normalization (XOR cancellation, rotation distribution)
- Relative rotation matching across multi-variable linear combinations for CorrelatedRotAnd
- Arithmetic dependency simplification (x + x -> x << 1, x - x -> 0, (x + y) - y -> x)
- Structural Hash-Consing (Common Subexpression Elimination across repeated helper calls)
"""

from dataclasses import dataclass
import itertools
from typing import Dict, FrozenSet, List, Optional, Set, Tuple, Union

_NEXT_NODE_ID = itertools.count(1)
_ACTIVE_WORDSIZE: int = 16


class CipherSpecificationError(ValueError, TypeError):
    """Raised when a Python cipher description contains invalid or unsupported constructs."""


def set_active_wordsize(wordsize: int) -> None:
    """Sets the active default wordsize for integer rotl/rotr calls."""
    global _ACTIVE_WORDSIZE
    _ACTIVE_WORDSIZE = wordsize


class IRNode:
    """Base class for all nodes in the traced CryptoIR DAG."""
    width: int
    node_id: int

    def __init__(self, width: int):
        self.width = width
        self.node_id = next(_NEXT_NODE_ID)

    def __post_init__(self):
        self.node_id = next(_NEXT_NODE_ID)


@dataclass(eq=False)
class InputVarNode(IRNode):
    name: str
    width: int


@dataclass(eq=False)
class ConstNode(IRNode):
    value: int
    width: int


@dataclass(eq=False)
class XorNode(IRNode):
    left: IRNode
    right: IRNode
    width: int


@dataclass(eq=False)
class RotateLeftNode(IRNode):
    operand: IRNode
    amount: int
    width: int


@dataclass(eq=False)
class ShiftLeftNode(IRNode):
    operand: IRNode
    amount: int
    width: int


@dataclass(eq=False)
class ShiftRightNode(IRNode):
    operand: IRNode
    amount: int
    width: int


@dataclass(eq=False)
class ModAddNode(IRNode):
    left: IRNode
    right: IRNode
    width: int
    is_sub: bool = False


@dataclass(eq=False)
class CorrelatedRotAndNode(IRNode):
    """Represents (u <<< alpha) & (u <<< beta) on a shared root expression u."""
    base: IRNode
    alpha: int
    beta: int
    width: int


@dataclass(eq=False)
class BitAndNode(IRNode):
    """Represents a general bitwise AND (u & v) between independent expressions."""
    left: IRNode
    right: IRNode
    width: int


# Global hash-consing caches keyed by deterministic node_id signature
_NODE_CACHE: Dict[Tuple, IRNode] = {}
_LINEAR_BASIS_CACHE: Dict[IRNode, FrozenSet[Tuple[IRNode, int]]] = {}


def reset_ir_caches() -> None:
    """Clears global IR hash-consing and linear basis caches."""
    _NODE_CACHE.clear()
    _LINEAR_BASIS_CACHE.clear()


def _get_cached_node(key: Tuple, factory) -> IRNode:
    if key not in _NODE_CACHE:
        _NODE_CACHE[key] = factory()
    return _NODE_CACHE[key]


def make_const(value: int, width: int) -> IRNode:
    val = value & ((1 << width) - 1)
    return _get_cached_node(("CONST", val, width), lambda: ConstNode(val, width))


def make_rotl(node: IRNode, amount: int) -> IRNode:
    w = node.width
    amount = amount % w
    if amount == 0 or (isinstance(node, ConstNode) and node.value == 0):
        return node
    # Distribute rotation over linear XOR basis and canonicalize
    basis = get_linear_basis(node)
    rotated_basis = frozenset((atom, (rot + amount) % w) for atom, rot in basis)
    return build_from_linear_basis(rotated_basis, w)


def make_rotr(node: IRNode, amount: int) -> IRNode:
    return make_rotl(node, (node.width - (amount % node.width)) % node.width)


def make_shl(node: IRNode, amount: int) -> IRNode:
    w = node.width
    if amount <= 0:
        return node
    if amount >= w or (isinstance(node, ConstNode) and node.value == 0):
        return make_const(0, w)
    if isinstance(node, XorNode):
        return make_xor(make_shl(node.left, amount), make_shl(node.right, amount))
    if isinstance(node, ShiftLeftNode):
        total = node.amount + amount
        if total >= w:
            return make_const(0, w)
        return _get_cached_node(
            ("SHL", node.operand.node_id, total, w),
            lambda: ShiftLeftNode(node.operand, total, w),
        )
    return _get_cached_node(("SHL", node.node_id, amount, w), lambda: ShiftLeftNode(node, amount, w))


def make_shr(node: IRNode, amount: int) -> IRNode:
    w = node.width
    if amount <= 0:
        return node
    if amount >= w or (isinstance(node, ConstNode) and node.value == 0):
        return make_const(0, w)
    if isinstance(node, XorNode):
        return make_xor(make_shr(node.left, amount), make_shr(node.right, amount))
    if isinstance(node, ShiftRightNode):
        total = node.amount + amount
        if total >= w:
            return make_const(0, w)
        return _get_cached_node(
            ("SHR", node.operand.node_id, total, w),
            lambda: ShiftRightNode(node.operand, total, w),
        )
    return _get_cached_node(("SHR", node.node_id, amount, w), lambda: ShiftRightNode(node, amount, w))


def get_linear_basis(node: IRNode) -> FrozenSet[Tuple[IRNode, int]]:
    """Decomposes a linear XOR/rotation expression into a canonical GF(2) set of (atom, rot)."""
    if node in _LINEAR_BASIS_CACHE:
        return _LINEAR_BASIS_CACHE[node]

    if isinstance(node, ConstNode) and node.value == 0:
        basis: FrozenSet[Tuple[IRNode, int]] = frozenset()
    elif isinstance(node, RotateLeftNode):
        sub_basis = get_linear_basis(node.operand)
        basis = frozenset((atom, (rot + node.amount) % node.width) for atom, rot in sub_basis)
    elif isinstance(node, XorNode):
        b1 = get_linear_basis(node.left)
        b2 = get_linear_basis(node.right)
        # Symmetric difference implements exact GF(2) cancellation: t ^ t = 0
        basis = b1 ^ b2
    else:
        basis = frozenset({(node, 0)})

    _LINEAR_BASIS_CACHE[node] = basis
    return basis


def _coalesce_complementary_shifts(
    basis: FrozenSet[Tuple[IRNode, int]], width: int
) -> FrozenSet[Tuple[IRNode, int]]:
    """Coalesces ((u << r) ^ (u >> (width - r))) inside a multi-term linear basis into (u, r)."""
    shl_map: Dict[Tuple[int, int, int], Tuple[IRNode, int]] = {}
    shr_map: Dict[Tuple[int, int, int], Tuple[IRNode, int]] = {}
    for atom, rot in basis:
        if isinstance(atom, ShiftLeftNode):
            shl_map[(atom.operand.node_id, atom.amount, rot)] = (atom, rot)
        elif isinstance(atom, ShiftRightNode):
            shr_map[(atom.operand.node_id, atom.amount, rot)] = (atom, rot)

    if not shl_map or not shr_map:
        return basis

    mutable_basis = set(basis)
    for (op_id, r1, rot), shl_term in list(shl_map.items()):
        r2 = width - r1
        shr_key = (op_id, r2, rot)
        if shr_key in shr_map and shl_term in mutable_basis and shr_map[shr_key] in mutable_basis:
            shr_term = shr_map[shr_key]
            mutable_basis.remove(shl_term)
            mutable_basis.remove(shr_term)
            operand = shl_term[0].operand
            # Unpack operand's own linear basis rotated by (rot + r1) % width
            for sub_atom, sub_rot in get_linear_basis(operand):
                combined_term = (sub_atom, (sub_rot + rot + r1) % width)
                if combined_term in mutable_basis:
                    mutable_basis.remove(combined_term)
                else:
                    mutable_basis.add(combined_term)

    return frozenset(mutable_basis)


def build_from_linear_basis(basis: FrozenSet[Tuple[IRNode, int]], width: int) -> IRNode:
    """Reconstructs a canonical hash-consed IRNode from a GF(2) linear basis."""
    basis = _coalesce_complementary_shifts(basis, width)
    if not basis:
        return make_const(0, width)

    key = ("LIN", width, tuple(sorted((atom.node_id, rot) for atom, rot in basis)))
    if key in _NODE_CACHE:
        return _NODE_CACHE[key]

    sorted_terms = sorted(basis, key=lambda item: (item[0].node_id, item[1]))
    term_nodes: List[IRNode] = []
    for atom, rot in sorted_terms:
        if rot == 0:
            term_nodes.append(atom)
        else:
            rot_key = ("ROTL_ATOM", atom.node_id, rot, width)
            rot_node = _get_cached_node(rot_key, lambda a=atom, r=rot: RotateLeftNode(a, r, width))
            _LINEAR_BASIS_CACHE[rot_node] = frozenset({(atom, rot)})
            term_nodes.append(rot_node)

    acc = term_nodes[0]
    for nxt in term_nodes[1:]:
        xor_key = ("XOR_PAIR", acc.node_id, nxt.node_id, width)
        acc = _get_cached_node(xor_key, lambda l=acc, r=nxt: XorNode(l, r, width))

    _NODE_CACHE[key] = acc
    _LINEAR_BASIS_CACHE[acc] = basis
    return acc


def make_xor(a: IRNode, b: IRNode) -> IRNode:
    w = a.width
    basis = get_linear_basis(a) ^ get_linear_basis(b)
    return build_from_linear_basis(basis, w)


def _match_rotation_pair(a: IRNode, b: IRNode, width: int) -> Optional[IRNode]:
    """Detects ((u << r1) | (u >> r2)) where (r1 + r2) % width == 0, including distributed XORs."""
    if isinstance(a, ShiftLeftNode) and isinstance(b, ShiftRightNode):
        if a.operand is b.operand and (a.amount + b.amount) % width == 0:
            return make_rotl(a.operand, a.amount % width)
    if isinstance(b, ShiftLeftNode) and isinstance(a, ShiftRightNode):
        if a.operand is b.operand and (a.amount + b.amount) % width == 0:
            return make_rotl(b.operand, b.amount % width)

    # Also support when u is an XorNode so (u << r1) and (u >> r2) were distributed over XOR
    b1 = get_linear_basis(a)
    b2 = get_linear_basis(b)
    if b1 and b2 and len(b1) == len(b2):
        if all(isinstance(atom, (ShiftLeftNode, ShiftRightNode)) for atom, _ in b1 | b2):
            coalesced = _coalesce_complementary_shifts(b1 ^ b2, width)
            if not any(isinstance(atom, (ShiftLeftNode, ShiftRightNode)) for atom, _ in coalesced):
                return build_from_linear_basis(coalesced, width)
    return None


def _match_correlated_rot_and(a: IRNode, b: IRNode) -> Optional[IRNode]:
    """Detects if `a` and `b` are rotated versions of the same underlying expression U.

    Works both for single variables `rotl(x, 8) & rotl(x, 1)` and for distributed
    multi-variable linear combinations `(rotl(x, 8) ^ rotl(y, 8)) & (rotl(x, 1) ^ rotl(y, 1))`.
    """
    w = a.width
    b1 = get_linear_basis(a)
    b2 = get_linear_basis(b)
    if not b1 or not b2 or len(b1) != len(b2):
        return None

    # Map each atom to its rotation in b1 and b2
    map1: Dict[IRNode, List[int]] = {}
    for atom, rot in b1:
        map1.setdefault(atom, []).append(rot)
    map2: Dict[IRNode, List[int]] = {}
    for atom, rot in b2:
        map2.setdefault(atom, []).append(rot)

    if set(map1.keys()) != set(map2.keys()):
        return None

    # Check if each atom appears once and with a uniform rotational offset delta
    deltas: Set[int] = set()
    ref_atom = None
    for atom in sorted(map1.keys(), key=lambda x: x.node_id):
        if len(map1[atom]) != 1 or len(map2[atom]) != 1:
            return None
        if ref_atom is None:
            ref_atom = atom
        d = (map1[atom][0] - map2[atom][0]) % w
        deltas.add(d)

    if len(deltas) != 1 or ref_atom is None:
        return None

    alpha = map1[ref_atom][0]
    beta = map2[ref_atom][0]
    if alpha == beta:
        return a

    if alpha < beta:
        alpha, beta = beta, alpha
        map_for_alpha = map2
    else:
        map_for_alpha = map1

    # Construct the canonical unrotated base U such that the alpha-operand == rotl(U, alpha)
    # and the beta-operand == rotl(U, beta)
    base_basis = frozenset((atom, (map_for_alpha[atom][0] - alpha) % w) for atom in map_for_alpha)
    base_node = build_from_linear_basis(base_basis, w)

    key = ("CORR_AND", base_node.node_id, alpha, beta, w)
    return _get_cached_node(
        key, lambda: CorrelatedRotAndNode(base=base_node, alpha=alpha, beta=beta, width=w)
    )


def make_and(a: IRNode, b: IRNode) -> IRNode:
    w = a.width
    if (isinstance(a, ConstNode) and a.value == 0) or (isinstance(b, ConstNode) and b.value == 0):
        return make_const(0, w)
    if a is b:
        return a

    corr = _match_correlated_rot_and(a, b)
    if corr is not None:
        return corr

    # Sort operands for commutative hash-consing so `(x & y)` and `(y & x)` share one node
    left, right = (a, b) if a.node_id <= b.node_id else (b, a)
    key = ("BIT_AND", left.node_id, right.node_id, w)
    return _get_cached_node(key, lambda: BitAndNode(left=left, right=right, width=w))


def make_add(a: IRNode, b: IRNode) -> IRNode:
    w = a.width
    if isinstance(a, ConstNode) and a.value == 0:
        return b
    if isinstance(b, ConstNode) and b.value == 0:
        return a
    # Dependency: x + x == 2*x == (x << 1) mod 2^w (deterministic linear shift, weight 0!)
    if a is b:
        return make_shl(a, 1)
    # Dependency: (x - y) + y == x and y + (x - y) == x
    if isinstance(a, ModAddNode) and a.is_sub and a.right is b:
        return a.left
    if isinstance(b, ModAddNode) and b.is_sub and b.right is a:
        return b.left
    # Dependency: (x + y) + (x - y) == 2*x == (x << 1)
    if isinstance(a, ModAddNode) and isinstance(b, ModAddNode) and (a.is_sub != b.is_sub):
        add_n, sub_n = (b, a) if a.is_sub else (a, b)
        if sub_n.left is add_n.left and sub_n.right is add_n.right:
            return make_shl(sub_n.left, 1)
        if sub_n.left is add_n.right and sub_n.right is add_n.left:
            return make_shl(sub_n.left, 1)

    # Commutative hash-consing so `(x + y)` and `(y + x)` share the exact same node and weight
    left, right = (a, b) if a.node_id <= b.node_id else (b, a)
    key = ("MOD_ADD", left.node_id, right.node_id, w)
    return _get_cached_node(key, lambda: ModAddNode(left=left, right=right, width=w, is_sub=False))


def make_sub(a: IRNode, b: IRNode) -> IRNode:
    w = a.width
    if isinstance(b, ConstNode) and b.value == 0:
        return a
    # Dependency: x - x == 0 (weight 0!)
    if a is b:
        return make_const(0, w)
    # Dependency: (x + y) - y == x and (y + x) - y == x
    if isinstance(a, ModAddNode) and not a.is_sub:
        if a.right is b:
            return a.left
        if a.left is b:
            return a.right
    # Dependency: x - (x - y) == y
    if isinstance(b, ModAddNode) and b.is_sub and b.left is a:
        return b.right
    # Dependency: (x - y) - (x - z) == z - y and (x - z) - (y - z) == x - y
    if isinstance(a, ModAddNode) and a.is_sub and isinstance(b, ModAddNode) and b.is_sub:
        if a.left is b.left:
            return make_sub(b.right, a.right)
        if a.right is b.right:
            return make_sub(a.left, b.left)
    # Dependency: (x + z) - (y + z) == x - y
    if isinstance(a, ModAddNode) and not a.is_sub and isinstance(b, ModAddNode) and not b.is_sub:
        if a.left is b.left:
            return make_sub(a.right, b.right)
        if a.left is b.right:
            return make_sub(a.right, b.left)
        if a.right is b.left:
            return make_sub(a.left, b.right)
        if a.right is b.right:
            return make_sub(a.left, b.left)

    key = ("MOD_SUB", a.node_id, b.node_id, w)
    return _get_cached_node(key, lambda: ModAddNode(left=a, right=b, width=w, is_sub=True))


class KeyWord:
    """Symbolic proxy for round keys, subkeys, and constants ignored in differential mode."""

    def __init__(self, name: str = "k"):
        self.name = name

    def __getitem__(self, item) -> "KeyWord":
        return KeyWord(f"{self.name}[{item}]")

    def rotl(self, amount: int) -> "KeyWord":
        if not isinstance(amount, int):
            raise TypeError("Rotation amount must be an integer constant")
        return self

    def rotr(self, amount: int) -> "KeyWord":
        if not isinstance(amount, int):
            raise TypeError("Rotation amount must be an integer constant")
        return self

    def __invert__(self) -> "KeyWord":
        return self

    def __lshift__(self, amount: int) -> "KeyWord":
        if not isinstance(amount, int):
            raise TypeError("Shift amount must be an integer constant")
        return self

    def __rshift__(self, amount: int) -> "KeyWord":
        if not isinstance(amount, int):
            raise TypeError("Shift amount must be an integer constant")
        return self

    def __xor__(self, other):
        if isinstance(other, (SymWord, int)):
            return other
        return self

    def __rxor__(self, other):
        return self.__xor__(other)

    def __add__(self, other):
        if isinstance(other, (SymWord, int)):
            return other
        return self

    def __radd__(self, other):
        return self.__add__(other)

    def __sub__(self, other):
        if isinstance(other, SymWord):
            return other
        if isinstance(other, int):
            return -other
        return self

    def __rsub__(self, other):
        if isinstance(other, (SymWord, int)):
            return other
        return self

    def __and__(self, other):
        if isinstance(other, SymWord):
            return other
        if isinstance(other, int):
            return 0
        return self

    def __rand__(self, other):
        return self.__and__(other)

    def __or__(self, other):
        if isinstance(other, (SymWord, int)):
            return other
        return self

    def __ror__(self, other):
        return self.__or__(other)

    def __mod__(self, modulus: int):
        return self

    def __int__(self) -> int:
        return 0


class SymWord:
    """Symbolic bit-vector word proxy that overloads Python operators to build CryptoIR."""

    def __init__(self, node: IRNode):
        self.node = node
        self.width = node.width

    @classmethod
    def input_var(cls, name: str, width: int) -> "SymWord":
        key = ("INPUT_VAR", name, width)
        node = _get_cached_node(key, lambda: InputVarNode(name=name, width=width))
        return cls(node)

    @property
    def full_mask(self) -> int:
        return (1 << self.width) - 1

    def rotl(self, amount: int) -> "SymWord":
        if not isinstance(amount, int):
            raise TypeError("Rotation amount must be an integer constant")
        return SymWord(make_rotl(self.node, amount))

    def rotr(self, amount: int) -> "SymWord":
        if not isinstance(amount, int):
            raise TypeError("Rotation amount must be an integer constant")
        return SymWord(make_rotr(self.node, amount))

    def __bool__(self) -> bool:
        raise TypeError(
            "Data-dependent branching (if/while/bool) on symbolic state word is not supported"
        )

    def __index__(self) -> int:
        raise TypeError(
            "Table/S-box indexing with symbolic state word is not supported in Phase 1"
        )

    def __lt__(self, other) -> bool:
        raise TypeError("Relational comparison (<) on symbolic state word is not supported")

    def __le__(self, other) -> bool:
        raise TypeError("Relational comparison (<=) on symbolic state word is not supported")

    def __gt__(self, other) -> bool:
        raise TypeError("Relational comparison (>) on symbolic state word is not supported")

    def __ge__(self, other) -> bool:
        raise TypeError("Relational comparison (>=) on symbolic state word is not supported")

    def __mul__(self, other) -> "SymWord":
        raise ValueError("Multiplication (*) is not supported in Phase 1 differential models")

    def __rmul__(self, other) -> "SymWord":
        raise ValueError("Multiplication (*) is not supported in Phase 1 differential models")

    def __floordiv__(self, other) -> "SymWord":
        raise ValueError("Division (//) is not supported in Phase 1 differential models")

    def __truediv__(self, other) -> "SymWord":
        raise ValueError("Division (/) is not supported in Phase 1 differential models")

    def __lshift__(self, amount: int) -> "SymWord":
        if not isinstance(amount, int):
            raise TypeError("Shift amount must be an integer constant")
        return SymWord(make_shl(self.node, amount))

    def __rshift__(self, amount: int) -> "SymWord":
        if not isinstance(amount, int):
            raise TypeError("Shift amount must be an integer constant")
        return SymWord(make_shr(self.node, amount))

    def __or__(self, other: Union["SymWord", KeyWord, int]) -> "SymWord":
        if isinstance(other, KeyWord):
            return self
        if isinstance(other, int):
            if other == 0:
                return self
            raise CipherSpecificationError(
                f"Bitwise OR with non-zero constant (0x{other:x}) is not supported in differential mode."
            )
        if self.node is other.node:
            return self
        rot_node = _match_rotation_pair(self.node, other.node, self.width)
        if rot_node is not None:
            return SymWord(rot_node)

        # Check if the user wrote (u << r1) | (u >> r2) for the wrong wordsize (e.g. 16 - r when wordsize=32)
        if isinstance(self.node, ShiftLeftNode) and isinstance(other.node, ShiftRightNode):
            shl_n, shr_n = self.node, other.node
        elif isinstance(other.node, ShiftLeftNode) and isinstance(self.node, ShiftRightNode):
            shl_n, shr_n = other.node, self.node
        else:
            shl_n, shr_n = None, None

        if shl_n is not None and shr_n is not None and shl_n.operand is shr_n.operand:
            shift_sum = shl_n.amount + shr_n.amount
            raise CipherSpecificationError(
                f"Invalid rotation idiom ((u << {shl_n.amount}) | (u >> {shr_n.amount})): "
                f"shift amounts sum to {shift_sum}, but cipher wordsize is {self.width}. "
                f"Hint: use ({self.width} - {shl_n.amount}) = {self.width - shl_n.amount} or transpiler.rotl(u, {shl_n.amount})."
            )

        raise CipherSpecificationError(
            "Bitwise OR ('|') between state words is only supported as part of a rotation idiom "
            f"((x << r) | (x >> ({self.width} - r))); use '&' and '^' for general boolean operations."
        )

    def __ror__(self, other: Union[KeyWord, int]) -> "SymWord":
        return self.__or__(other)

    def __xor__(self, other: Union["SymWord", KeyWord, int]) -> "SymWord":
        if isinstance(other, (int, KeyWord)):
            # In single-key differential cryptanalysis, Δ(x ^ const) = Δ(x ^ key) = Δx
            return self
        rot_node = _match_rotation_pair(self.node, other.node, self.width)
        if rot_node is not None:
            return SymWord(rot_node)
        return SymWord(make_xor(self.node, other.node))

    def __rxor__(self, other: Union[KeyWord, int]) -> "SymWord":
        return self.__xor__(other)

    def __invert__(self) -> "SymWord":
        # Δ(~x) = Δ(x ^ 0xffff...f) = Δx
        return self

    def __and__(self, other: Union["SymWord", KeyWord, int]) -> "SymWord":
        if isinstance(other, KeyWord):
            return self
        if isinstance(other, int):
            if (other & self.full_mask) == self.full_mask:
                return self
            if other == 0:
                return SymWord(make_const(0, self.width))
            # Check if other is a full mask for a different wordsize (e.g. 0xFFFF when wordsize=32)
            if other > 0 and (other & (other + 1)) == 0:
                mask_bits = other.bit_length()
                raise CipherSpecificationError(
                    f"Constant bitmask 0x{other:x} is a {mask_bits}-bit mask, "
                    f"but cipher wordsize is {self.width} (expected 0x{self.full_mask:x}). "
                    f"Hint: set WORDSIZE = {mask_bits} or update the mask to 0x{self.full_mask:x}."
                )
            raise CipherSpecificationError(
                f"Partial constant bitmask 0x{other:x} is not supported for width {self.width} "
                f"(expected full mask 0x{self.full_mask:x})."
            )
        return SymWord(make_and(self.node, other.node))

    def __rand__(self, other: Union[KeyWord, int]) -> "SymWord":
        return self.__and__(other)

    def __add__(self, other: Union["SymWord", KeyWord, int]) -> "SymWord":
        if isinstance(other, (int, KeyWord)):
            # Ignore key / round-constant modular addition: (x + k) -> x
            return self
        return SymWord(make_add(self.node, other.node))

    def __radd__(self, other: Union[KeyWord, int]) -> "SymWord":
        return self.__add__(other)

    def __sub__(self, other: Union["SymWord", KeyWord, int]) -> "SymWord":
        if isinstance(other, (int, KeyWord)):
            # Ignore key / round-constant modular subtraction: (x - k) -> x
            return self
        return SymWord(make_sub(self.node, other.node))

    def __rsub__(self, other: Union[KeyWord, int]) -> "SymWord":
        if isinstance(other, (int, KeyWord)):
            return self
        return SymWord(make_sub(other.node, self.node))

    def __mod__(self, modulus: int) -> "SymWord":
        if modulus == (1 << self.width):
            return self
        raise ValueError(f"Unsupported modulus {modulus} for width {self.width}")


def rotl(x: Union[SymWord, KeyWord, int], r: int, wordsize: Optional[int] = None):
    """Helper rotation left function that works on SymWord, KeyWord, and Python ints."""
    if not isinstance(r, int):
        raise TypeError("Rotation amount must be an integer constant")
    if isinstance(x, (SymWord, KeyWord)):
        return x.rotl(r)
    w = wordsize or _ACTIVE_WORDSIZE
    r %= w
    return ((x << r) | (x >> (w - r))) & ((1 << w) - 1)


def rotr(x: Union[SymWord, KeyWord, int], r: int, wordsize: Optional[int] = None):
    """Helper rotation right function that works on SymWord, KeyWord, and Python ints."""
    if not isinstance(r, int):
        raise TypeError("Rotation amount must be an integer constant")
    if isinstance(x, (SymWord, KeyWord)):
        return x.rotr(r)
    w = wordsize or _ACTIVE_WORDSIZE
    r %= w
    return ((x >> r) | (x << (w - r))) & ((1 << w) - 1)
