#!/usr/bin/env python3
"""Circuit inputs from the synthetic taps: <pkg>/Prover.toml and <pkg>/src/tests/vectors.nr."""

import json
import os
import re
from dataclasses import dataclass
from typing import Any, NoReturn

import bin_tree
import verify_emv_reference as vc
from gen_synthetic import FIXTURES, KINDS

ROOT = os.path.dirname(FIXTURES)
CA_KEYS = os.path.join(FIXTURES, "test-ca-keys.json")
BIN_TABLE = os.path.join(FIXTURES, "bin-table.json")
DISCLOSE_ALL = 0xF
TODAY = 2609  # YYMM, pinned so the committed outputs don't change every month
SCOPE = 0x5C09E  # any field element; the emv crate derives real ones

LIMB_BITS = 120

Inputs = dict[str, Any]


@dataclass
class Struct:
    name: str
    fields: dict[str, Any]


def limbs(modulus: bytes) -> list[int]:
    """120-bit little-endian limbs."""
    n, count = int.from_bytes(modulus, "big"), (len(modulus) * 8 + LIMB_BITS - 1) // LIMB_BITS
    return [(n >> (LIMB_BITS * i)) & ((1 << LIMB_BITS) - 1) for i in range(count)]


def circuit_global(pkg: str, name: str) -> int:
    main_nr = open(os.path.join(ROOT, pkg, "src", "main.nr")).read()
    match = re.search(rf"^global {name}: u32 = (\d+);$", main_nr, re.MULTILINE)
    if match is None:
        raise SystemExit(f"{pkg}/src/main.nr: no global {name}")
    return int(match.group(1))


def fail(pkg: str, what: str) -> NoReturn:
    raise SystemExit(f"fixtures/{pkg}.json: {what} does not verify")


def bin_membership(pan: str, table: dict[str, Any], tree: list[dict[int, int]]) -> Struct:
    r = bin_tree.find(table, int(pan[: bin_tree.PREFIX_DIGITS]))
    if r is None:
        raise SystemExit(f"fixtures/bin-table.json: no range holds PAN prefix {pan[: bin_tree.PREFIX_DIGITS]}")

    fields = {"low": r["low"], "high": r["high"], "country": r["country"], "card_type": bin_tree.TYPES[r["type"]]}
    fields |= {"brand": table["brands"].index(r["brand"]) + 1, "commercial": r["commercial"], "slot": r["slot"], "siblings": bin_tree.path(tree, r["slot"])}

    return Struct("BinMembership", fields)


def circuit_inputs(pkg: str, capks: vc.CAKeys, table: dict[str, Any], tree: list[dict[int, int]]) -> Inputs:
    doc = json.load(open(os.path.join(FIXTURES, pkg + ".json")))
    els = vc.elements(doc)

    def h(tag: str) -> bytes:
        return vc.h2b(els.get(tag, {}).get("value"))

    rid = doc["selectedAid"][:10]
    ca, issuer = b"", None
    for exp, mod, _ in capks.get((rid, els["8F"]["value"]), []):
        issuer, _ = vc.verify_issuer_cert(h("90"), mod, exp, h("92"), h("9F32"))
        if issuer:
            ca = mod
            break
    if not issuer:
        fail(pkg, "issuer certificate")
    static = vc.static_data_to_authenticate(doc, els)
    icc_cert, _ = vc.verify_icc_cert(h("9F46"), issuer["modulus"], issuer["exponent"], h("9F48"), h("9F47"), static)
    if not icc_cert or not icc_cert["hash_ok"]:
        fail(pkg, "ICC certificate")

    t = doc["terminal"]
    nonce, amount, currency = (bytes(t[k]) for k in ("nonce", "amountAuthorised", "currencyCode"))
    td = nonce + amount + currency + h("9F69") if pkg == "visa_fdda" else nonce
    sd, _ = vc.verify_sdad(h("9F4B"), icc_cert["modulus"], icc_cert["exponent"], [("", td)])
    if not sd or not sd["matched"]:
        fail(pkg, "signed dynamic data")

    challenge = Struct("Challenge", {"nonce": list(nonce), "today_yymm": TODAY, "scope": SCOPE, "disclosure": DISCLOSE_ALL})
    x: Inputs = {"trust_anchors": Struct("TrustAnchors", {"ca_modulus": limbs(ca), "bin_root": bin_tree.root(tree)}), "challenge": challenge}
    issuer = {"issuer_pubkey_cert": list(h("90"))}
    icc = {"issuer_pubkey_exponent": h("9F32")[0], "icc_pubkey_cert": list(h("9F46")), "icc_pubkey_exponent": h("9F47")[0]}
    sdad = {"signed_dynamic_app_data": list(h("9F4B"))}

    if pkg == "visa_fdda":
        x["transaction"] = Struct("Transaction", {"amount_authorised": list(amount), "currency_code": list(currency)})
        card = issuer | icc | sdad | {"card_auth_related_data": list(h("9F69"))}
    else:
        capacity = circuit_global(pkg, "STATIC_DATA_MAX_BYTE_LEN")
        assert len(static) <= capacity
        static_data = {"storage": list(static) + [0] * (capacity - len(static)), "len": len(static)}
        card = issuer | {"issuer_pubkey_remainder": list(h("92"))} | icc | {"static_data_to_authenticate": static_data} | sdad

    x["card"] = Struct("Card", card)
    x["bin_membership"] = bin_membership(icc_cert["pan"], table, tree)
    x["icc_modulus"] = list(icc_cert["modulus"])

    return x


def toml_value(v: Any) -> str:
    if isinstance(v, bool):
        return str(v).lower()

    if isinstance(v, list):
        return "[" + ", ".join(f'"{i}"' if i >= 1 << 63 else str(i) for i in v) + "]"

    return f'"{v}"' if isinstance(v, int) and v >= 1 << 63 else str(v)


def to_toml(x: Inputs) -> str:
    """Each parameter a table; a struct or bounded vector inside one a subtable."""
    out: list[str] = []

    def table(path: str, fields: dict[str, Any]) -> None:
        nested = {k: v for k, v in fields.items() if isinstance(v, (dict, Struct))}
        out.append(f"\n[{path}]")
        out.extend(f"{k} = {toml_value(v)}" for k, v in fields.items() if k not in nested)
        for k, v in nested.items():
            table(f"{path}.{k}", v.fields if isinstance(v, Struct) else v)

    for k, v in x.items():
        table(k, v.fields if isinstance(v, Struct) else v)

    return "\n".join(out).lstrip("\n") + "\n"


def noir_value(v: Any) -> str:
    if isinstance(v, bool):
        return str(v).lower()

    if isinstance(v, Struct):
        return f"{v.name} {{ " + ", ".join(f"{k}: {noir_value(f)}" for k, f in v.fields.items()) + " }"

    if isinstance(v, dict):
        return f"BoundedVec::from_parts({noir_value(v['storage'])}, {v['len']})"

    if isinstance(v, list):
        return "[" + ", ".join(hex(i) for i in v) + "]"

    return hex(v)


def to_noir(x: Inputs, icc_modulus: list[int]) -> str:
    """A global per `main` parameter, named after it."""
    emv_types = sorted(v.name for k, v in x.items() if k != "card")
    out = [
        "// Generated by scripts/gen_circuit_inputs.py from the synthetic taps in fixtures/.",
        "use crate::Card;",
        f"use emv::{{{', '.join(emv_types)}}};",
        "",
        f"pub global ICC_MODULUS: [u8; {len(icc_modulus)}] = {noir_value(icc_modulus)};",
    ]
    out += [f"\npub global {k.upper()}: {v.name} = {noir_value(v)};" for k, v in x.items()]
    return "\n".join(out) + "\n"


def main() -> None:
    capks = vc.load_CA_pubkeys(CA_KEYS)
    table, tree = bin_tree.load(BIN_TABLE)
    if "%064x" % bin_tree.root(tree) != table["tree"]["root"]:
        raise SystemExit("fixtures/bin-table.json: root does not match its ranges")

    inputs = {pkg: circuit_inputs(pkg, capks, table, tree) for pkg in KINDS}

    for pkg, x in inputs.items():
        icc_modulus = x.pop("icc_modulus")
        open(os.path.join(ROOT, pkg, "Prover.toml"), "w").write(to_toml(x))
        open(os.path.join(ROOT, pkg, "src", "tests", "vectors.nr"), "w").write(to_noir(x, icc_modulus))
        print(f"wrote {pkg}/Prover.toml, {pkg}/src/tests/vectors.nr")


if __name__ == "__main__":
    main()
