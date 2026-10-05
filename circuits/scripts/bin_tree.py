"""The emv crate's BIN table Merkle tree (emv/src/bin_table), for fixtures and circuit inputs."""

import json
from typing import Any

import poseidon2
from emv_layout import BITS_PER_BYTE, DECIMAL_BASE

TREE_DEPTH = 24
TREE_ARITY = 2
PAN_PREFIX_DIGIT_COUNT = 12
COUNTRY_CODE_DIGIT_COUNT = 3
TYPES = {"credit": 1, "debit": 2, "prepaid": 3}
LEAF_VERSION = 1

PAN_PREFIX_BIT_LEN = (DECIMAL_BASE**PAN_PREFIX_DIGIT_COUNT - 1).bit_length()
COUNTRY_CODE_BIT_LEN = (DECIMAL_BASE**COUNTRY_CODE_DIGIT_COUNT - 1).bit_length()
CARD_TYPE_BIT_LEN = max(TYPES.values()).bit_length()
BRAND_CODE_BIT_LEN = BITS_PER_BYTE
COMMERCIAL_FLAG_BIT_LEN = 1
LEAF = "low + high·2^40 + country·2^80 + type·2^90 + brand·2^92 + commercial·2^100 + 2^101; 0 if empty. type: credit 1, debit 2, prepaid 3."
NODE = "Poseidon2 (noir-lang/poseidon v0.3.0, t = 4) of the left and right child."


def leaf(entry: dict[str, Any], brands: list[str]) -> int:
    fields = [
        (int(entry["commercial"]), COMMERCIAL_FLAG_BIT_LEN),
        (brands.index(entry["brand"]) + 1, BRAND_CODE_BIT_LEN),
        (TYPES[entry["type"]], CARD_TYPE_BIT_LEN),
        (entry["country"], COUNTRY_CODE_BIT_LEN),
        (entry["high"], PAN_PREFIX_BIT_LEN),
        (entry["low"], PAN_PREFIX_BIT_LEN),
    ]
    acc = LEAF_VERSION
    for value, bits in fields:
        assert 0 <= value < 1 << bits
        acc = (acc << bits) | value
    return acc


def empty_roots() -> list[int]:
    roots = [0]
    for _ in range(TREE_DEPTH):
        roots.append(poseidon2.hash([roots[-1], roots[-1]]))
    return roots


def levels(leaves: dict[int, int]) -> list[dict[int, int]]:
    """Non-empty nodes by level, leaves first."""
    empty = empty_roots()
    out = [dict(leaves)]
    for level in range(TREE_DEPTH):
        nodes = out[-1]
        parents = {i // TREE_ARITY for i in nodes}
        out.append({p: poseidon2.hash([nodes.get(TREE_ARITY * p + child, empty[level]) for child in range(TREE_ARITY)]) for p in sorted(parents)})
    return out


def root(tree: list[dict[int, int]]) -> int:
    return tree[TREE_DEPTH].get(0, empty_roots()[TREE_DEPTH])


def path(tree: list[dict[int, int]], slot: int) -> list[int]:
    empty = empty_roots()
    return [tree[level].get((slot >> level) ^ 1, empty[level]) for level in range(TREE_DEPTH)]


def load(path_: str) -> tuple[dict[str, Any], list[dict[int, int]]]:
    """A table in data/bin-table.json's format, and its tree."""
    doc = json.load(open(path_, encoding="utf-8"))
    tree = levels({r["slot"]: leaf(r, doc["brands"]) for r in doc["ranges"]})
    return doc, tree


def dump(other_keys: dict[str, Any], brands: list[str], ranges: list[dict[str, Any]]) -> str:
    """The layout of the emv crate's `BinTable::to_json`, with the root."""
    tree = {"depth": TREE_DEPTH, "leaf": LEAF, "node": NODE, "prefix_digits": PAN_PREFIX_DIGIT_COUNT}
    tree["root"] = "%064x" % root(levels({r["slot"]: leaf(r, brands) for r in ranges}))
    members = [*other_keys.items(), ("tree", tree), ("brands", brands)]
    out = "{\n" + "".join(
        f"  {json.dumps(k)}: {json.dumps(v, indent=2, sort_keys=True, ensure_ascii=False).replace(chr(10), chr(10) + '  ')},\n" for k, v in members
    )
    lines = ",\n".join(
        "    " + json.dumps({k: r[k] for k in ("slot", "low", "high", "country", "type", "brand", "commercial")}, ensure_ascii=False) for r in ranges
    )
    return out + '  "ranges": [\n' + lines + "\n  ]\n}\n"


def find(doc: dict[str, Any], prefix: int) -> dict[str, Any] | None:
    return next((r for r in doc["ranges"] if r["low"] <= prefix <= r["high"]), None)
