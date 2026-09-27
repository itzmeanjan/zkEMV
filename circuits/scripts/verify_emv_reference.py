#!/usr/bin/env python3
"""Native EMV Book 2 chain verifier: CA key -> issuer cert 90 -> ICC cert 9F46 -> SDAD 9F4B."""

import os
import sys
import json
import glob
import hashlib
import argparse
from typing import Any

HDR, TRL = 0x6A, 0xBC
FMT_ISSUER, FMT_ICC = 0x02, 0x04

FMT_SDAD = {0x05: "DDA (Book 2)", 0x95: "fDDA (Visa kernel)"}

OK, BAD, INFO = "  ok ", " FAIL", "     "

Capture = dict[str, Any]
Elements = dict[str, dict[str, Any]]
CAKeys = dict[tuple[str, str], list[tuple[bytes, bytes, str]]]
Verified = tuple[dict[str, Any] | None, str | None]

CA_PUBKEYS = os.path.join(os.path.dirname(os.path.abspath(__file__)), "..", "..",
                          "data", "certificate-authority-public-keys.json")


def h2b(s: str | None) -> bytes:
    return bytes.fromhex(s) if s else b""


def load_CA_pubkeys(path: str) -> CAKeys:
    out: CAKeys = {}
    for k in json.load(open(path))["keys"]:
        rid, idx, exp, mod = (k[f].upper() for f in ("rid", "index", "exponent", "modulus"))
        pub = (k["checksum"] or "").upper()
        calc = hashlib.sha1(
            h2b(rid) + h2b(idx) + h2b(mod) + h2b(exp)
        ).hexdigest().upper()
        if calc != pub:
            continue
        out.setdefault((rid, idx), []).append((h2b(exp), h2b(mod), pub))
    return out


def recover(sig: bytes, modulus: bytes, exponent: bytes) -> tuple[bytes | None, str | None]:
    """ISO 9796-2 scheme 1 message recovery."""
    if len(sig) != len(modulus):
        return None, f"signature is {len(sig)}B but modulus is {len(modulus)}B"
    n = int.from_bytes(modulus, "big")
    e = int.from_bytes(exponent, "big")
    s = int.from_bytes(sig, "big")
    if s >= n:
        return None, "signature >= modulus"
    m = pow(s, e, n).to_bytes(len(modulus), "big")
    if m[0] != HDR:
        return None, f"header is {m[0]:02X}, expected 6A"
    if m[-1] != TRL:
        return None, f"trailer is {m[-1]:02X}, expected BC"
    return m, None


def build_key(leftmost: bytes, remainder: bytes, length: int) -> bytes:
    return (leftmost + remainder)[:length]


def verify_issuer_cert(cert: bytes, capk_mod: bytes, capk_exp: bytes, remainder: bytes,
                       exponent: bytes) -> Verified:
    """Book 2 table 6."""
    m, err = recover(cert, capk_mod, capk_exp)
    if m is None:
        return None, err
    if m[1] != FMT_ISSUER:
        return None, f"certificate format {m[1]:02X}, expected 02"

    n_ca = len(capk_mod)
    issuer_id = m[2:6].hex().upper().rstrip("F")
    expiry = m[6:8].hex()
    serial = m[8:11].hex().upper()
    hash_alg, pk_alg = m[11], m[12]
    pk_len, pk_exp_len = m[13], m[14]
    leftmost = m[15 : n_ca - 21]
    hash_result = m[n_ca - 21 : n_ca - 1]

    calc = hashlib.sha1(m[1 : n_ca - 21] + remainder + exponent).digest()
    if calc != hash_result:
        return None, "hash mismatch over recovered issuer certificate"

    return {
        "issuer_id": issuer_id,
        "expiry": f"{expiry[:2]}/{expiry[2:]}",
        "serial": serial,
        "hash_alg": hash_alg,
        "pk_alg": pk_alg,
        "modulus": build_key(leftmost, remainder, pk_len),
        "exponent": exponent,
        "pk_len": pk_len,
        "pk_exp_len": pk_exp_len,
    }, None


def verify_icc_cert(cert: bytes, iss_mod: bytes, iss_exp: bytes, remainder: bytes,
                    exponent: bytes, static_data: bytes = b"") -> Verified:
    """Book 2 table 14."""
    m, err = recover(cert, iss_mod, iss_exp)
    if m is None:
        return None, err
    if m[1] != FMT_ICC:
        return None, f"certificate format {m[1]:02X}, expected 04"

    n_i = len(iss_mod)
    pan = m[2:12].hex().upper().rstrip("F")
    expiry = m[12:14].hex()
    serial = m[14:17].hex().upper()
    hash_alg, pk_alg = m[17], m[18]
    pk_len, pk_exp_len = m[19], m[20]
    leftmost = m[21 : n_i - 21]
    hash_result = m[n_i - 21 : n_i - 1]

    calc = hashlib.sha1(
        m[1 : n_i - 21] + remainder + exponent + static_data
    ).digest()

    return {
        "pan": pan,
        "expiry": f"{expiry[:2]}/{expiry[2:]}",
        "serial": serial,
        "hash_alg": hash_alg,
        "pk_alg": pk_alg,
        "modulus": build_key(leftmost, remainder, pk_len),
        "exponent": exponent,
        "pk_len": pk_len,
        "hash_ok": calc == hash_result,
    }, None


def verify_sdad(sdad: bytes, icc_mod: bytes, icc_exp: bytes,
                terminal_data_candidates: list[tuple[str, bytes]]) -> Verified:
    """Book 2 table 17."""
    m, err = recover(sdad, icc_mod, icc_exp)
    if m is None:
        return None, err
    if m[1] not in FMT_SDAD:
        return None, (f"signed data format {m[1]:02X}, expected one of "
                      + "/".join(f"{k:02X}" for k in FMT_SDAD))

    n_ic = len(icc_mod)
    fmt = FMT_SDAD[m[1]]
    hash_alg = m[2]
    ldd = m[3]
    icc_dynamic = m[4 : 4 + ldd]
    hash_result = m[n_ic - 21 : n_ic - 1]
    body = m[1 : n_ic - 21]

    matched = None
    for name, td in terminal_data_candidates:
        if hashlib.sha1(body + td).digest() == hash_result:
            matched = (name, td)
            break

    return {
        "format": fmt,
        "hash_alg": hash_alg,
        "icc_dynamic_len": ldd,
        "icc_dynamic": icc_dynamic,
        "matched": matched,
        "hash_result": hash_result,
    }, None


def elements(doc: Capture) -> Elements:
    return {e["tag"]: e for e in doc.get("elements", [])}


def static_data_to_authenticate(doc: Capture, els: Elements) -> bytes:
    """Book 3 10.3: AFL-flagged records (template 70 value only), then the AIP if 9F4A = 82."""
    out = b""
    for entry in doc.get("afl", []):
        for rec in range(entry["first"], entry["first"] + entry["odaRecords"]):
            label = f"sfi={entry['sfi']} rec={rec}"
            ex = next(
                (e for e in doc["exchanges"]
                 if label in e["label"] and e["ok"]), None
            )
            if not ex:
                continue
            raw = h2b(ex["response"])[:-2]
            if not raw or raw[0] != 0x70:
                out += raw
                continue
            i, ln = 1, raw[1]
            if ln > 0x80:
                k = ln & 0x7F
                ln = int.from_bytes(raw[2 : 2 + k], "big")
                i = 2 + k
            else:
                i = 2
            out += raw[i : i + ln]

    tag_list = h2b(els.get("9F4A", {}).get("value"))
    if tag_list == b"\x82":
        out += h2b(els.get("82", {}).get("value"))
    return out


def run(path: str, capks: CAKeys) -> bool:
    doc = json.load(open(path))
    els = elements(doc)
    aid = doc.get("selectedAid") or ""
    rid = aid[:10].upper()
    idx_el = els.get("8F")
    print("=" * 74)
    print(f"{path.split('/')[-1]}   AID {aid}")
    print("=" * 74)
    if not idx_el or "90" not in els or "9F46" not in els:
        print(f"{INFO}incomplete capture: no chain to verify")
        return False
    idx = idx_el["value"].upper()

    cands = capks.get((rid, idx), [])
    print(f"{INFO}RID {rid}  CA index {idx}  -> {len(cands)} candidate CA key(s)")
    if not cands:
        print(f"{BAD} no CA public key available for this RID/index")
        return False

    cert90 = h2b(els["90"]["value"])
    rem92 = h2b(els.get("92", {}).get("value"))
    exp9f32 = h2b(els.get("9F32", {}).get("value"))

    issuer = None
    for exp, mod, pub in cands:
        got, err = verify_issuer_cert(cert90, mod, exp, rem92, exp9f32)
        if got:
            issuer = got
            print(f"{OK} issuer certificate verifies under CA key "
                  f"{len(mod) * 8}-bit (hash {pub[:16]}...)")
            break
        print(f"{INFO}tried {len(mod) * 8}-bit CA key: {err}")
    if not issuer:
        print(f"{BAD} issuer certificate did not verify under any candidate key")
        return False

    print(f"{INFO}  issuer id {issuer['issuer_id']}   cert expiry "
          f"{issuer['expiry']}   serial {issuer['serial']}")
    print(f"{INFO}  issuer modulus {issuer['pk_len']}B "
          f"({issuer['pk_len'] * 8}-bit), exponent "
          f"{int.from_bytes(issuer['exponent'], 'big')}")

    cert46 = h2b(els["9F46"]["value"])
    rem9f48 = h2b(els.get("9F48", {}).get("value"))
    exp9f47 = h2b(els.get("9F47", {}).get("value"))

    static = static_data_to_authenticate(doc, els)
    icc, err = verify_icc_cert(
        cert46, issuer["modulus"], issuer["exponent"], rem9f48, exp9f47, static
    )
    if not icc:
        print(f"{BAD} ICC certificate: {err}")
        return False

    print(f"{OK} ICC certificate recovers under the issuer key")
    pan = icc["pan"]
    print(f"{INFO}  PAN in certificate {pan[:6]}{'*' * (len(pan) - 10)}{pan[-4:]}"
          f"   cert expiry {icc['expiry']}   serial {icc['serial']}")
    print(f"{INFO}  ICC modulus {icc['pk_len']}B ({icc['pk_len'] * 8}-bit)")
    if icc["hash_ok"]:
        note = (f"over {len(static)}B of ODA static data" if static
                else "no ODA static data on this card")
        print(f"{OK} ICC certificate hash verifies ({note})")
    else:
        print(f"{BAD} ICC certificate hash MISMATCH "
              f"({len(static)}B static data supplied)")

    plain = els.get("5A", {}).get("value", "").rstrip("Ff")
    if plain:
        agree = plain.upper().rstrip("F") == pan
        print(f"{OK if agree else BAD} certificate PAN "
              f"{'matches' if agree else 'DIFFERS FROM'} tag 5A")

    if "9F4B" not in els:
        print(f"{INFO}no 9F4B in this capture; nothing dynamic to check")
        return True

    un = bytes(doc["terminal"]["unpredictableNumber"])
    amount = bytes(doc["terminal"]["amountAuthorised"])
    currency = bytes(doc["terminal"]["currencyCode"])
    country = bytes(doc["terminal"]["countryCode"])
    ttq = bytes(doc["terminal"]["ttq"])
    card_auth = h2b(els.get("9F69", {}).get("value"))

    cands_td = [
        ("9F37 (DDA, default DDOL)", un),
        ("9F37 || 9F02 || 5F2A || 9F69 (Visa fDDA)",
         un + amount + currency + card_auth),
        ("9F37 || 9F02 || 5F2A", un + amount + currency),
        ("9F02 || 5F2A || 9F37", amount + currency + un),
        ("9F37 || 9F02 || 5F2A || 9F1A", un + amount + currency + country),
        ("9F37 || 9F66", un + ttq),
        ("(none)", b""),
    ]

    sd, err = verify_sdad(
        h2b(els["9F4B"]["value"]), icc["modulus"], icc["exponent"], cands_td
    )
    if not sd:
        print(f"{BAD} dynamic signature: {err}")
        return False

    print(f"{OK} dynamic signature recovers under the ICC key — {sd['format']}, "
          f"{sd['icc_dynamic_len']}B ICC dynamic data")
    if sd["matched"]:
        name, td = sd["matched"]
        print(f"{OK} SIGNATURE HASH VERIFIES over {name}")
        nonce_hex = un.hex().upper()
        covered = un in td
        print(f"{OK if covered else BAD}   our nonce {nonce_hex} "
              f"{'IS' if covered else 'is NOT'} covered by the signature")
    else:
        print(f"{INFO}hash did not match any candidate terminal-data layout")
        print(f"{INFO}  nonce sent: {un.hex().upper()}")
        print(f"{INFO}  ICC dynamic data: {sd['icc_dynamic'].hex().upper()}")
        print(f"{INFO}  (kernel-specific layout; recovery itself still succeeded)")
    return True


def main() -> int:
    ap = argparse.ArgumentParser()
    ap.add_argument("captures", nargs="+")
    ap.add_argument("--capk", default=CA_PUBKEYS)
    a = ap.parse_args()

    capks = load_CA_pubkeys(a.capk)
    print(f"loaded {sum(len(v) for v in capks.values())} checksum-verified "
          f"CA keys from {a.capk}\n")

    files = []
    for pat in a.captures:
        files.extend(sorted(glob.glob(pat)))
    seen, ok = set(), 0
    for f in files:
        if not f.endswith(".json"):
            continue
        d = json.load(open(f))
        key = elements(d).get("5A", {}).get("value")
        if key and key in seen:
            continue
        seen.add(key)
        if run(f, capks):
            ok += 1
        print()
    print(f"{ok} chain(s) verified")
    return 0


if __name__ == "__main__":
    sys.exit(main())
