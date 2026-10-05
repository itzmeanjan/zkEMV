#!/usr/bin/env python3
"""Generates synthetic card tap data"""

import hashlib
import json
import os
import random
from typing import Any, Callable, TypedDict

import bin_tree
import verify_emv_reference as vc
from emv_layout import (
    AIP_TAG_LIST,
    AMOUNT_AUTHORISED_BYTE_LEN,
    BER_LENGTH_BYTE_LEN,
    BER_LONG_LENGTH_FLAG,
    BITS_PER_BYTE,
    DECIMAL_BASE,
    ENVELOPE_BYTE_LEN,
    EXPONENT_BYTE_LEN,
    FMT_ICC_CERT,
    FMT_ISSUER_CERT,
    FMT_SDAD_DDA,
    HASH_ALG_SHA1,
    ISSUER_ID_BYTE_LEN,
    NIBBLE_PAD,
    NIBBLES_PER_BYTE,
    NONCE_BYTE_LEN,
    PAD_BYTE,
    PAN_BYTE_LEN,
    PK_ALG_RSA,
    RECOVERED_DATA_HEADER,
    RECOVERED_DATA_TRAILER,
    RSA_EXPONENT,
    SERIAL_BYTE_LEN,
    STATUS_WORD_SUCCESS,
    VISA_FMT_SDAD_FDDA,
)

HERE = os.path.dirname(os.path.abspath(__file__))
FIXTURES = os.path.join(os.path.dirname(HERE), "fixtures")
SEED = 2609

# The test CA key's index; unused by any real key under these RIDs in data/.
CA_INDEX = "EE"
CA_PUBKEY_BIT_LEN = 1984
CERT_EXPIRY_MMYY = bytes.fromhex("1249")
BIN_DIGIT_COUNT = 6
BER_ONE_LENGTH_BYTE = BER_LONG_LENGTH_FLAG | BER_LENGTH_BYTE_LEN

# Sizes of the synthetic dynamic data, as on the corpus cards.
ATC_BYTE_LEN = 2
ICC_DYNAMIC_NUMBER_BYTE_LEN = 8
# Card Authentication Related Data (9F69): fDDA version, the card's random number, CTQ.
FDDA_VERSION = bytes([0x01])
CARD_RANDOM_BYTE_LEN = 4
CTQ_BYTE_LEN = 2
MC_STATIC_DATA_BYTE_LEN = 131

# RSA key generation: two primes, each with its top two bits set; Miller-Rabin.
PRIME_COUNT = 2
TOP_BITS = 0b11
TOP_BIT_COUNT = 2
SMALL_PRIMES = (2, 3, 5, 7, 11, 13, 17, 19, 23, 29, 31, 37)
MILLER_RABIN_ROUNDS = 40


def luhn(digits: str) -> str:
    total = 0
    for i, c in enumerate(reversed(digits)):
        d = int(c) * (2 if i % 2 == 0 else 1)
        total += d - (DECIMAL_BASE - 1) if d >= DECIMAL_BASE else d
    return digits + str((DECIMAL_BASE - total % DECIMAL_BASE) % DECIMAL_BASE)


class RsaKey:
    """RSA with public exponent 3, signing ISO 9796-2 scheme 1 blocks as EMV Book 2 does."""

    def __init__(self, n: int, d: int, bits: int) -> None:
        self.n, self.d, self.bits = n, d, bits

    @classmethod
    def generate(cls, bits: int, rng: random.Random) -> "RsaKey":
        while True:
            p, q = cls._prime(bits // PRIME_COUNT, rng), cls._prime(bits // PRIME_COUNT, rng)
            n = p * q
            if p != q and n.bit_length() == bits:
                return cls(n, pow(RSA_EXPONENT, -1, (p - 1) * (q - 1)), bits)

    @staticmethod
    def _prime(bits: int, rng: random.Random) -> int:
        """Top two bits set, so the product of two is exactly 2*bits long; p = 2 mod 3, so
        exponent 3 is invertible."""
        while True:
            p = rng.getrandbits(bits) | (TOP_BITS << (bits - TOP_BIT_COUNT)) | 1
            if p % RSA_EXPONENT == RSA_EXPONENT - 1 and RsaKey._is_probable_prime(p, rng):
                return p

    @staticmethod
    def _is_probable_prime(n: int, rng: random.Random) -> bool:
        if n < 2:
            return False
        for p in SMALL_PRIMES:
            if n % p == 0:
                return n == p
        d, r = n - 1, 0
        while d % 2 == 0:
            d, r = d // 2, r + 1
        for _ in range(MILLER_RABIN_ROUNDS):
            x = pow(rng.randrange(2, n - 1), d, n)
            if x in (1, n - 1):
                continue
            for _ in range(r - 1):
                x = pow(x, 2, n)
                if x == n - 1:
                    break
            else:
                return False
        return True

    def modulus(self) -> bytes:
        return self.n.to_bytes(self.bits // BITS_PER_BYTE, "big")

    def sign(self, body: bytes, hashed_tail: bytes) -> bytes:
        """6A || body || SHA-1(body || hashed_tail) || BC, signed as one RSA block: scheme 1
        recovers the whole message, so there is no separate padding."""
        digest = hashlib.sha1(body + hashed_tail).digest()
        x = int.from_bytes(bytes([RECOVERED_DATA_HEADER]) + body + digest + bytes([RECOVERED_DATA_TRAILER]), "big")
        assert x < self.n
        s = pow(x, self.d, self.n)
        assert pow(s, RSA_EXPONENT, self.n) == x
        return s.to_bytes(self.bits // BITS_PER_BYTE, "big")


def split_key(modulus: bytes, space: int) -> tuple[bytes, bytes]:
    if len(modulus) > space:
        return modulus[:space], modulus[space:]
    return modulus + bytes([PAD_BYTE]) * (space - len(modulus)), b""


def certificate(signer: RsaKey, fmt: int, owner_id: bytes, modulus: bytes, serial: bytes, static: bytes = b"") -> tuple[bytes, bytes]:
    """Book 2 tables 6 (issuer) and 14 (ICC)."""
    head = bytes([fmt]) + owner_id + CERT_EXPIRY_MMYY + serial + bytes([HASH_ALG_SHA1, PK_ALG_RSA, len(modulus), EXPONENT_BYTE_LEN])
    leftmost, remainder = split_key(modulus, signer.bits // BITS_PER_BYTE - ENVELOPE_BYTE_LEN - len(head))
    cert = signer.sign(head + leftmost, remainder + bytes([RSA_EXPONENT]) + static)
    return cert, remainder


def sdad(icc: RsaKey, fmt: int, dynamic: bytes, terminal_data: bytes) -> bytes:
    """Book 2 table 17."""
    body = bytes([fmt, HASH_ALG_SHA1, len(dynamic)]) + dynamic
    body += bytes([PAD_BYTE]) * (icc.bits // BITS_PER_BYTE - ENVELOPE_BYTE_LEN - len(body))
    return icc.sign(body, terminal_data)


def tlv(tag: str, value: bytes) -> bytes:
    n = len(value)
    length = bytes([n]) if n < BER_LONG_LENGTH_FLAG else bytes([BER_ONE_LENGTH_BYTE, n])
    return bytes.fromhex(tag) + length + value


def mc_static_record(pan_bcd8: bytes, aip: bytes, rng: random.Random) -> bytes:
    """The ODA record, in the tag order and lengths of the Mastercard corpus card.
    Values are synthetic; the circuit hashes this record but never parses it."""
    fields = [
        ("5F25", bytes.fromhex("260101")),  # effective date YYMMDD
        ("5F24", bytes.fromhex("491231")),  # expiry date YYMMDD
        ("5A", pan_bcd8),
        ("5F34", b"\x01"),  # PAN sequence number
        ("9F07", b"\xff\x00"),  # application usage control
        ("8C", rng.randbytes(33)),  # CDOL1
        ("8D", rng.randbytes(12)),  # CDOL2
        ("8E", rng.randbytes(14)),  # CVM list
        ("9F0D", rng.randbytes(5)),  # IAC default
        ("9F0E", rng.randbytes(5)),  # IAC denial
        ("9F0F", rng.randbytes(5)),  # IAC online
        ("5F28", bytes.fromhex("0999")),  # issuer country (unassigned)
        ("9F4A", b"\x82"),  # SDA tag list: the AIP
    ]
    value = b"".join(tlv(t, v) for t, v in fields)
    assert len(value) + len(aip) == MC_STATIC_DATA_BYTE_LEN
    return value


class Kind(TypedDict):
    aid: str
    issuer_pubkey_bit_len: int
    icc_pubkey_bit_len: int
    pan: str
    sdad_format: int
    sdad_source: str
    aip: str
    static_record: Callable[[bytes, bytes, random.Random], bytes] | None


# Card kinds, as measured on real taps.
KINDS: dict[str, Kind] = {
    "visa_fdda": {
        "aid": "A0000000031010",
        "issuer_pubkey_bit_len": 1408,
        "icc_pubkey_bit_len": 1024,
        # MII 9: not a payment card, so no real PAN can collide.
        "pan": "999990000000000",
        "sdad_format": VISA_FMT_SDAD_FDDA,
        "sdad_source": "GPO",
        "aip": "2000",
        "static_record": None,
    },
    "mastercard_dda": {
        "aid": "A0000000041010",
        "issuer_pubkey_bit_len": 1920,
        "icc_pubkey_bit_len": 1152,
        "pan": "999991000000000",
        "sdad_format": FMT_SDAD_DDA,
        "sdad_source": "INTERNAL AUTHENTICATE",
        "aip": "1980",
        "static_record": mc_static_record,
    },
}


# BIN table attributes of each kind's 6-digit BIN. Countries are ISO 3166's user-assigned codes.
BIN_ATTRIBUTES: dict[str, dict[str, Any]] = {
    "visa_fdda": {"country": 999, "type": "credit", "brand": "VISA", "commercial": False},
    "mastercard_dda": {"country": 998, "type": "prepaid", "brand": "MASTERCARD", "commercial": True},
}


def bin_table() -> str:
    bin_span = DECIMAL_BASE ** (bin_tree.PAN_PREFIX_DIGIT_COUNT - BIN_DIGIT_COUNT)
    spans = sorted((int(kind["pan"][:BIN_DIGIT_COUNT]) * bin_span, pkg) for pkg, kind in KINDS.items())
    ranges = [{"slot": i, "low": low, "high": low + bin_span - 1, **BIN_ATTRIBUTES[pkg]} for i, (low, pkg) in enumerate(spans)]
    brands = sorted({r["brand"] for r in ranges})
    return bin_tree.dump({"source": {"repository": "scripts/gen_synthetic.py"}}, brands, ranges)


def element(tag: str, value: bytes, source: str) -> dict[str, Any]:
    return {"tag": tag, "value": value.hex().upper(), "length": len(value), "source": source}


def synthesize(pkg: str, kind: Kind, ca: RsaKey, rng: random.Random) -> dict[str, Any]:
    issuer = RsaKey.generate(kind["issuer_pubkey_bit_len"], rng)
    icc = RsaKey.generate(kind["icc_pubkey_bit_len"], rng)

    pan = luhn(kind["pan"])
    pan_bcd8 = bytes.fromhex(pan)
    pan_bcd10 = bytes.fromhex(pan.ljust(PAN_BYTE_LEN * NIBBLES_PER_BYTE, NIBBLE_PAD))
    issuer_id = bytes.fromhex(pan[:BIN_DIGIT_COUNT].ljust(ISSUER_ID_BYTE_LEN * NIBBLES_PER_BYTE, NIBBLE_PAD))
    aip = bytes.fromhex(kind["aip"])

    cert90, rem92 = certificate(ca, FMT_ISSUER_CERT, issuer_id, issuer.modulus(), rng.randbytes(SERIAL_BYTE_LEN))

    exchanges: list[dict[str, Any]] = []
    afl = [{"sfi": 1, "first": 1, "last": 1, "odaRecords": 0}]
    static = b""
    if kind["static_record"]:
        record = kind["static_record"](pan_bcd8, aip, rng)
        static = record + aip
        afl = [{"sfi": 2, "first": 1, "last": 1, "odaRecords": 1}]
        exchanges.append(
            {
                "label": "READ RECORD sfi=2 rec=1",
                "command": "00B2011400",
                "response": (tlv("70", record) + STATUS_WORD_SUCCESS).hex().upper(),
                "sw": STATUS_WORD_SUCCESS.hex().upper(),
                "ok": True,
            }
        )

    cert9f46, rem9f48 = certificate(issuer, FMT_ICC_CERT, pan_bcd10, icc.modulus(), rng.randbytes(SERIAL_BYTE_LEN), static)
    assert not rem9f48, "no kind in the corpus has an ICC remainder (9F48)"

    # TTQ and country code are placeholders; no circuit reads them.
    terminal = {
        "ttq": [0x36, 0x00, 0x40, 0x00],
        "countryCode": [0x08, 0x40],
        "currencyCode": [0x08, 0x40],
        "amountAuthorised": [0] * AMOUNT_AUTHORISED_BYTE_LEN,
        "nonce": list(rng.randbytes(NONCE_BYTE_LEN)),
    }
    nonce = bytes(terminal["nonce"])
    elements = [
        element("82", aip, "GPO"),
        element("8F", bytes.fromhex(CA_INDEX), "READ RECORD"),
        element("90", cert90, "READ RECORD"),
        element("9F32", bytes([RSA_EXPONENT]), "READ RECORD"),
        element("9F46", cert9f46, "READ RECORD"),
        element("9F47", bytes([RSA_EXPONENT]), "READ RECORD"),
        element("5A", pan_bcd8, "READ RECORD"),
    ]
    if rem92:
        elements.append(element("92", rem92, "READ RECORD"))

    if pkg == "visa_fdda":
        atc = rng.randbytes(ATC_BYTE_LEN)
        dynamic = bytes([len(atc)]) + atc
        card_auth = FDDA_VERSION + rng.randbytes(CARD_RANDOM_BYTE_LEN) + bytes(CTQ_BYTE_LEN)
        td = nonce + bytes(terminal["amountAuthorised"]) + bytes(terminal["currencyCode"]) + card_auth
        # PDOL as on the Visa corpus cards: 9F66 9F02 9F03 9F1A 95 5F2A 9A 9C 9F37.
        pdol = bytes.fromhex("9F66049F02069F03069F1A0295055F2A029A039C019F3704")
        elements += [
            element("9F38", pdol, "SELECT AID"),
            element("9F69", card_auth, "GPO"),
            element("9F36", atc, "GPO"),
        ]
    else:
        icc_dynamic_number = rng.randbytes(ICC_DYNAMIC_NUMBER_BYTE_LEN)
        dynamic = bytes([len(icc_dynamic_number)]) + icc_dynamic_number
        td = nonce
        elements.append(element("9F4A", AIP_TAG_LIST, "READ RECORD"))

    elements.append(element("9F4B", sdad(icc, kind["sdad_format"], dynamic, td), kind["sdad_source"]))
    return {
        "synthetic": True,
        "notes": f"Synthetic {pkg} tap from scripts/gen_synthetic.py (seed {SEED}). " "Test CA key, fake PAN; no real card data.",
        "selectedAid": kind["aid"],
        "aip": kind["aip"],
        "afl": afl,
        "terminal": terminal,
        "exchanges": exchanges,
        "elements": elements,
        # Lets a test re-sign 9F4B for a nonce of its choosing.
        "testIccKey": {"modulus": icc.modulus().hex().upper(), "privateExponent": icc.d.to_bytes(icc.bits // BITS_PER_BYTE, "big").hex().upper()},
    }


def main() -> None:
    # One seeded rng feeds every key, serial and nonce, including the Miller-Rabin
    # witnesses: reordering any draw changes all output after it.
    rng = random.Random(SEED)
    ca = RsaKey.generate(CA_PUBKEY_BIT_LEN, rng)
    ca_mod = ca.modulus().hex().upper()
    exponent = f"{RSA_EXPONENT:02X}"
    os.makedirs(FIXTURES, exist_ok=True)

    keys: list[dict[str, Any]] = []
    for pkg, kind in KINDS.items():
        doc = synthesize(pkg, kind, ca, rng)
        open(os.path.join(FIXTURES, pkg + ".json"), "w").write(json.dumps(doc, indent=2) + "\n")
        rid = kind["aid"][:10]
        checksum = hashlib.sha1(bytes.fromhex(rid + CA_INDEX + ca_mod + exponent)).hexdigest().upper()
        keys.append(
            {
                "scheme": "TEST",
                "rid": rid,
                "index": CA_INDEX,
                "exponent": exponent,
                "modulus_bits": CA_PUBKEY_BIT_LEN,
                "modulus": ca_mod,
                "checksum": checksum,
                "expires": None,
            }
        )
        print(f"wrote fixtures/{pkg}.json")

    table = {
        "sources": [{"url": "scripts/gen_synthetic.py", "retrieved": None}],
        "fields": json.load(open(vc.CA_PUBKEYS))["fields"],
        "keys": keys,
    }
    open(os.path.join(FIXTURES, "test-ca-keys.json"), "w").write(json.dumps(table, indent=2) + "\n")
    print("wrote fixtures/test-ca-keys.json")

    open(os.path.join(FIXTURES, "bin-table.json"), "w", encoding="utf-8").write(bin_table())
    print("wrote fixtures/bin-table.json")


if __name__ == "__main__":
    main()
