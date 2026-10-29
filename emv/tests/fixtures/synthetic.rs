//! Synthetic taps, one per card kind, with the structure of the real captures: key widths, tags
//! and data layout as measured, under a test CA key and with a fake PAN.

use std::iter;

use emv::{Attributes, BinTable, CardType, PAN_PREFIX_DIGIT_COUNT, Range, Scheme};
use rand_chacha::rand_core::SeedableRng;
use serde::{Deserialize, Serialize};
use serde_json::json;
use sha1::{Digest, Sha1};

use crate::{
    GENERATOR, Rng,
    layout::{
        AIP_TAG_LIST, AMOUNT_AUTHORISED_BYTE_LEN, BER_LONG_LENGTH_FLAG, DECIMAL_BASE, ENVELOPE_BYTE_LEN, FMT_ICC_CERT, FMT_ISSUER_CERT, FMT_SDAD_DDA,
        HASH_ALG_SHA1, ISSUER_ID_BYTE_LEN, LE_ANY, NIBBLE_PAD, NIBBLES_PER_BYTE, NONCE_BYTE_LEN, P2_RECORD_NUMBER, PAD_BYTE, PAN_BYTE_LEN, PK_ALG_RSA,
        READ_RECORD_CLA, READ_RECORD_INS, RECORD_TEMPLATE_TAG, RSA_EXPONENT, SERIAL_BYTE_LEN, SFI_SHIFT, STATUS_WORD_SUCCESS, VISA_FMT_SDAD_FDDA,
    },
    merkle::TREE_DEPTH,
    random_bytes,
    rsa::RsaKey,
};

const SEED: u64 = 2609;
/// Unused by any real key under these RIDs in the repository's CA key table.
const CA_INDEX: u8 = 0xEE;
const CA_PUBKEY_BIT_LEN: usize = Scheme::VisaFdda.ca_pubkey_bit_len();
const CERT_EXPIRY_MMYY: [u8; 2] = [0x12, 0x49];
const EXPONENT_BYTE_LEN: u8 = 1;
const BIN_DIGIT_COUNT: usize = 6;
const BER_ONE_LENGTH_BYTE: u8 = BER_LONG_LENGTH_FLAG | 1;

const ATC_BYTE_LEN: usize = 2;
const ICC_DYNAMIC_NUMBER_BYTE_LEN: usize = 8;
/// Card Authentication Related Data `9F69`: fDDA version, the card's random number, CTQ.
const FDDA_VERSION: u8 = 0x01;
const CARD_RANDOM_BYTE_LEN: usize = 4;
const CTQ_BYTE_LEN: usize = 2;
const MC_STATIC_DATA_BYTE_LEN: usize = 131;
const VISA_STATIC_DATA_BYTE_LEN: usize = 22;

/// The ODA record's template `70` value, from the PAN and AIP.
type StaticRecord = fn(&[u8], &[u8], &mut Rng) -> Vec<u8>;

/// The record that the AFL marks for offline data authentication.
struct OdaRecord {
    sfi: u8,
    number: u8,
    value: StaticRecord,
}

/// As measured on real taps.
pub(crate) struct Kind {
    pub(crate) scheme: Scheme,
    pub(crate) package: &'static str,
    /// `fixtures/<name>.json`.
    pub(crate) name: &'static str,
    /// `<package>/src/tests/<vectors>.nr`.
    pub(crate) vectors: &'static str,
    aid: &'static str,
    /// Without the check digit. MII 9: not a payment card, so no real PAN can collide.
    pan: &'static str,
    sdad_format: u8,
    sdad_source: &'static str,
    aip: [u8; 2],
    oda_record: Option<OdaRecord>,
    /// Of the PAN's 6-digit BIN. Countries are ISO 3166's user-assigned codes.
    bin: BinAttributes,
}

struct BinAttributes {
    country: u16,
    card_type: CardType,
    brand: &'static str,
    commercial: bool,
}

/// New kinds go last: one generator feeds them all, in order.
pub(crate) const KINDS: [Kind; 3] = [
    Kind {
        scheme: Scheme::VisaFdda,
        package: "visa_fdda",
        name: "visa_fdda",
        vectors: "vectors",
        aid: "A0000000031010",
        pan: "999990000000000",
        sdad_format: VISA_FMT_SDAD_FDDA,
        sdad_source: "GPO",
        aip: [0x20, 0x00],
        oda_record: None,
        bin: BinAttributes {
            country: 999,
            card_type: CardType::Credit,
            brand: "VISA",
            commercial: false,
        },
    },
    Kind {
        scheme: Scheme::MastercardDda,
        package: "mastercard_dda",
        name: "mastercard_dda",
        vectors: "vectors",
        aid: "A0000000041010",
        pan: "999991000000000",
        sdad_format: FMT_SDAD_DDA,
        sdad_source: "INTERNAL AUTHENTICATE",
        aip: [0x19, 0x80],
        oda_record: Some(OdaRecord {
            sfi: 2,
            number: 1,
            value: mc_static_record,
        }),
        bin: BinAttributes {
            country: 998,
            card_type: CardType::Prepaid,
            brand: "MASTERCARD",
            commercial: true,
        },
    },
    // How the other Visa corpus cards differ: the ICC certificate also signs an ODA record and
    // the AIP, and the SDAD has Book 2's format 05.
    Kind {
        scheme: Scheme::VisaFdda,
        package: "visa_fdda",
        name: "visa_fdda_oda",
        vectors: "vectors_oda",
        aid: "A0000000031010",
        pan: "999992000000000",
        sdad_format: FMT_SDAD_DDA,
        sdad_source: "GPO",
        aip: [0x20, 0x00],
        oda_record: Some(OdaRecord {
            sfi: 3,
            number: 3,
            value: visa_static_record,
        }),
        bin: BinAttributes {
            country: 997,
            card_type: CardType::Debit,
            brand: "VISA",
            commercial: false,
        },
    },
];

pub(crate) struct Fixtures {
    /// A tap per [`KINDS`] entry.
    pub(crate) taps: Vec<SyntheticTap>,
    pub(crate) ca_modulus: Vec<u8>,
    pub(crate) ca_table: String,
    pub(crate) bin_table: String,
}

/// A tap's JSON, and what its certificates certify.
pub(crate) struct SyntheticTap {
    pub(crate) json: String,
    pub(crate) pan: String,
    pub(crate) icc_modulus: Vec<u8>,
    pub(crate) static_data: Vec<u8>,
}

#[derive(Serialize)]
#[serde(rename_all = "camelCase")]
struct TapJson {
    synthetic: bool,
    notes: String,
    selected_aid: &'static str,
    aip: String,
    afl: [AflEntry; 1],
    terminal: Terminal,
    exchanges: Vec<Exchange>,
    elements: Vec<Element>,
    /// Lets a test re-sign `9F4B` for a nonce of its choosing.
    test_icc_key: TestIccKey,
}

#[derive(Serialize)]
#[serde(rename_all = "camelCase")]
struct AflEntry {
    sfi: u8,
    first: u8,
    last: u8,
    oda_records: u8,
}

#[derive(Serialize)]
#[serde(rename_all = "camelCase")]
struct Terminal {
    ttq: [u8; 4],
    country_code: [u8; 2],
    currency_code: [u8; 2],
    amount_authorised: [u8; AMOUNT_AUTHORISED_BYTE_LEN],
    nonce: Vec<u8>,
}

#[derive(Serialize)]
struct Exchange {
    label: String,
    command: String,
    response: String,
    sw: String,
    ok: bool,
}

#[derive(Serialize)]
struct Element {
    tag: &'static str,
    value: String,
    length: usize,
    source: &'static str,
}

#[derive(Serialize)]
#[serde(rename_all = "camelCase")]
struct TestIccKey {
    modulus: String,
    private_exponent: String,
}

#[derive(Serialize)]
struct CaTable {
    sources: [Source; 1],
    fields: CaKeyFields,
    keys: Vec<CaKey>,
}

#[derive(Serialize)]
struct Source {
    url: &'static str,
    retrieved: Option<&'static str>,
}

#[derive(Deserialize)]
struct CaTableHeader {
    fields: CaKeyFields,
}

#[derive(Deserialize, Serialize)]
#[serde(deny_unknown_fields)]
struct CaKeyFields {
    scheme: String,
    rid: String,
    index: String,
    exponent: String,
    modulus_bits: String,
    modulus: String,
    checksum: String,
    expires: String,
}

#[derive(Serialize)]
struct CaKey {
    scheme: &'static str,
    rid: String,
    index: String,
    exponent: String,
    modulus_bits: usize,
    modulus: String,
    checksum: String,
    expires: Option<&'static str>,
}

/// `ca_keys` is the repository's CA key table, whose field descriptions the test table
/// repeats.
pub(crate) fn generate(ca_keys: &[u8]) -> Fixtures {
    let mut rng = Rng::seed_from_u64(SEED);
    let ca = RsaKey::generate(CA_PUBKEY_BIT_LEN, &mut rng);
    let taps = KINDS.iter().map(|kind| tap(kind, &ca, &mut rng)).collect();

    let modulus = ca.modulus();
    let mut schemes: Vec<Scheme> = Vec::new();
    for kind in &KINDS {
        if !schemes.contains(&kind.scheme) {
            schemes.push(kind.scheme);
        }
    }
    let keys = schemes
        .into_iter()
        .map(|scheme| CaKey {
            scheme: "TEST",
            rid: const_hex::encode_upper(scheme.rid()),
            index: const_hex::encode_upper([CA_INDEX]),
            exponent: const_hex::encode_upper([RSA_EXPONENT]),
            modulus_bits: CA_PUBKEY_BIT_LEN,
            modulus: const_hex::encode_upper(&modulus),
            checksum: const_hex::encode_upper(
                Sha1::new()
                    .chain_update(scheme.rid())
                    .chain_update([CA_INDEX])
                    .chain_update(&modulus)
                    .chain_update([RSA_EXPONENT])
                    .finalize(),
            ),
            expires: None,
        })
        .collect();
    let ca_table = CaTable {
        sources: [Source {
            url: GENERATOR,
            retrieved: None,
        }],
        fields: serde_json::from_slice::<CaTableHeader>(ca_keys).unwrap().fields,
        keys,
    };

    Fixtures {
        taps,
        ca_modulus: modulus,
        ca_table: pretty(&ca_table),
        bin_table: bin_table(),
    }
}

fn tap(kind: &Kind, ca: &RsaKey, rng: &mut Rng) -> SyntheticTap {
    let issuer = RsaKey::generate(kind.scheme.issuer_pubkey_bit_len(), rng);
    let icc = RsaKey::generate(kind.scheme.icc_pubkey_bit_len(), rng);

    let pan = luhn(kind.pan);
    let pan_bcd = const_hex::decode(&pan).unwrap();
    let pan_padded = padded_bcd(&pan, PAN_BYTE_LEN);
    let issuer_id = padded_bcd(&pan[..BIN_DIGIT_COUNT], ISSUER_ID_BYTE_LEN);

    let serial = random_bytes(rng, SERIAL_BYTE_LEN);
    let (cert90, rem92) = certificate(ca, FMT_ISSUER_CERT, &issuer_id, &issuer.modulus(), &serial, &[]);

    let (afl, exchanges, static_data) = match &kind.oda_record {
        Some(oda) => oda.read(&pan_bcd, &kind.aip, rng),
        None => (
            AflEntry {
                sfi: 1,
                first: 1,
                last: 1,
                oda_records: 0,
            },
            Vec::new(),
            Vec::new(),
        ),
    };

    let serial = random_bytes(rng, SERIAL_BYTE_LEN);
    let (cert9f46, rem9f48) = certificate(&issuer, FMT_ICC_CERT, &pan_padded, &icc.modulus(), &serial, &static_data);
    assert!(rem9f48.is_empty(), "no kind in the corpus has an ICC remainder (9F48)");

    // TTQ and country code are placeholders; no circuit reads them.
    let terminal = Terminal {
        ttq: [0x36, 0x00, 0x40, 0x00],
        country_code: [0x08, 0x40],
        currency_code: [0x08, 0x40],
        amount_authorised: [0; AMOUNT_AUTHORISED_BYTE_LEN],
        nonce: random_bytes(rng, NONCE_BYTE_LEN),
    };
    let mut elements = vec![
        element("82", &kind.aip, "GPO"),
        element("8F", &[CA_INDEX], "READ RECORD"),
        element("90", &cert90, "READ RECORD"),
        element("9F32", &[RSA_EXPONENT], "READ RECORD"),
        element("9F46", &cert9f46, "READ RECORD"),
        element("9F47", &[RSA_EXPONENT], "READ RECORD"),
        element("5A", &pan_bcd, "READ RECORD"),
    ];
    if !rem92.is_empty() {
        elements.push(element("92", &rem92, "READ RECORD"));
    }

    let (dynamic_number, terminal_data) = match kind.scheme {
        Scheme::VisaFdda => {
            let atc = random_bytes(rng, ATC_BYTE_LEN);
            let card_auth = [&[FDDA_VERSION][..], &random_bytes(rng, CARD_RANDOM_BYTE_LEN), &[0; CTQ_BYTE_LEN]].concat();
            let terminal_data = [&terminal.nonce[..], &terminal.amount_authorised, &terminal.currency_code, &card_auth].concat();
            // PDOL as on the Visa corpus cards: 9F66 9F02 9F03 9F1A 95 5F2A 9A 9C 9F37.
            let pdol = const_hex::decode("9F66049F02069F03069F1A0295055F2A029A039C019F3704").unwrap();
            elements.extend([
                element("9F38", &pdol, "SELECT AID"),
                element("9F69", &card_auth, "GPO"),
                element("9F36", &atc, "GPO"),
            ]);
            if kind.oda_record.is_some() {
                elements.push(element("9F4A", &AIP_TAG_LIST, "READ RECORD"));
            }
            (atc, terminal_data)
        }
        Scheme::MastercardDda => {
            elements.push(element("9F4A", &AIP_TAG_LIST, "READ RECORD"));
            (random_bytes(rng, ICC_DYNAMIC_NUMBER_BYTE_LEN), terminal.nonce.clone())
        }
    };
    let dynamic = [&[byte_len(&dynamic_number)][..], &dynamic_number].concat();
    elements.push(element("9F4B", &sdad(&icc, kind.sdad_format, &dynamic, &terminal_data), kind.sdad_source));

    let json = pretty(&TapJson {
        synthetic: true,
        notes: format!(
            "Synthetic {} tap from {GENERATOR} (seed {SEED}). Test CA key, fake PAN; no real card data.",
            kind.name
        ),
        selected_aid: kind.aid,
        aip: const_hex::encode_upper(kind.aip),
        afl: [afl],
        terminal,
        exchanges,
        elements,
        test_icc_key: TestIccKey {
            modulus: const_hex::encode_upper(icc.modulus()),
            private_exponent: const_hex::encode_upper(icc.private_exponent()),
        },
    });
    SyntheticTap {
        json,
        pan,
        icc_modulus: icc.modulus(),
        static_data,
    }
}

impl OdaRecord {
    /// The AFL entry that marks the record, its READ RECORD, and the static data: its template
    /// `70` value, then the AIP.
    fn read(&self, pan_bcd: &[u8], aip: &[u8], rng: &mut Rng) -> (AflEntry, Vec<Exchange>, Vec<u8>) {
        let record = (self.value)(pan_bcd, aip, rng);
        let afl = AflEntry {
            sfi: self.sfi,
            first: self.number,
            last: self.number,
            oda_records: 1,
        };
        let exchange = Exchange {
            label: format!("READ RECORD sfi={} rec={}", self.sfi, self.number),
            command: const_hex::encode_upper([READ_RECORD_CLA, READ_RECORD_INS, self.number, self.sfi << SFI_SHIFT | P2_RECORD_NUMBER, LE_ANY]),
            response: const_hex::encode_upper([tlv(&[RECORD_TEMPLATE_TAG], &record), STATUS_WORD_SUCCESS.to_vec()].concat()),
            sw: const_hex::encode_upper(STATUS_WORD_SUCCESS),
            ok: true,
        };
        (afl, vec![exchange], [&record[..], aip].concat())
    }
}

/// Book 2 tables 6 (issuer) and 14 (ICC): the certificate and the key's remainder.
fn certificate(signer: &RsaKey, format: u8, owner_id: &[u8], modulus: &[u8], serial: &[u8], static_data: &[u8]) -> (Vec<u8>, Vec<u8>) {
    let head = [
        &[format][..],
        owner_id,
        &CERT_EXPIRY_MMYY,
        serial,
        &[HASH_ALG_SHA1, PK_ALG_RSA, byte_len(modulus), EXPONENT_BYTE_LEN],
    ]
    .concat();
    let key_space = signer.byte_len() - ENVELOPE_BYTE_LEN - head.len();
    let (leftmost, remainder) = if modulus.len() > key_space {
        (modulus[..key_space].to_vec(), modulus[key_space..].to_vec())
    } else {
        ([modulus, &vec![PAD_BYTE; key_space - modulus.len()]].concat(), Vec::new())
    };
    let cert = signer.sign(&[head, leftmost].concat(), &[&remainder[..], &[RSA_EXPONENT], static_data].concat());
    (cert, remainder)
}

/// Book 2 table 17.
fn sdad(icc: &RsaKey, format: u8, dynamic: &[u8], terminal_data: &[u8]) -> Vec<u8> {
    let mut body = [&[format, HASH_ALG_SHA1, byte_len(dynamic)][..], dynamic].concat();
    body.resize(icc.byte_len() - ENVELOPE_BYTE_LEN, PAD_BYTE);
    icc.sign(&body, terminal_data)
}

/// The ODA record, in the tag order and lengths of the Mastercard corpus card. Values are
/// synthetic; the circuit hashes this record but never parses it.
fn mc_static_record(pan_bcd: &[u8], aip: &[u8], rng: &mut Rng) -> Vec<u8> {
    let fields: Vec<(&[u8], Vec<u8>)> = vec![
        (&[0x5F, 0x25], vec![0x26, 0x01, 0x01]), // effective date YYMMDD
        (&[0x5F, 0x24], vec![0x49, 0x12, 0x31]), // expiry date YYMMDD
        (&[0x5A], pan_bcd.to_vec()),
        (&[0x5F, 0x34], vec![0x01]),           // PAN sequence number
        (&[0x9F, 0x07], vec![0xFF, 0x00]),     // application usage control
        (&[0x8C], random_bytes(rng, 33)),      // CDOL1
        (&[0x8D], random_bytes(rng, 12)),      // CDOL2
        (&[0x8E], random_bytes(rng, 14)),      // CVM list
        (&[0x9F, 0x0D], random_bytes(rng, 5)), // IAC default
        (&[0x9F, 0x0E], random_bytes(rng, 5)), // IAC denial
        (&[0x9F, 0x0F], random_bytes(rng, 5)), // IAC online
        (&[0x5F, 0x28], vec![0x09, 0x99]),     // issuer country (unassigned)
        (&[0x9F, 0x4A], AIP_TAG_LIST.to_vec()),
    ];
    let value: Vec<u8> = fields.iter().flat_map(|(tag, value)| tlv(tag, value)).collect();
    assert_eq!(value.len() + aip.len(), MC_STATIC_DATA_BYTE_LEN);
    value
}

/// The ODA record, in the tag order and lengths of the Visa corpus card with static data. On it,
/// the PAN and expiry date are signed.
fn visa_static_record(pan_bcd: &[u8], aip: &[u8], _: &mut Rng) -> Vec<u8> {
    let fields: Vec<(&[u8], Vec<u8>)> = vec![
        (&[0x5F, 0x24], vec![0x49, 0x12, 0x31]), // expiry date YYMMDD
        (&[0x5A], pan_bcd.to_vec()),
        (&[0x9F, 0x4A], AIP_TAG_LIST.to_vec()),
    ];
    let value: Vec<u8> = fields.iter().flat_map(|(tag, value)| tlv(tag, value)).collect();
    assert_eq!(value.len() + aip.len(), VISA_STATIC_DATA_BYTE_LEN);
    value
}

/// Each kind's BIN as a range, in a table whose brands are sorted.
fn bin_table() -> String {
    let span = u64::from(DECIMAL_BASE).pow(u32::try_from(PAN_PREFIX_DIGIT_COUNT - BIN_DIGIT_COUNT).unwrap());
    let mut ranges: Vec<(u64, &Kind)> = KINDS.iter().map(|k| (k.pan[..BIN_DIGIT_COUNT].parse::<u64>().unwrap() * span, k)).collect();
    ranges.sort_by_key(|&(low, _)| low);
    let mut brands: Vec<&str> = KINDS.iter().map(|k| k.bin.brand).collect();
    brands.sort_unstable();
    brands.dedup();

    let empty = json!({
        "source": {"repository": GENERATOR},
        "tree": {"depth": TREE_DEPTH, "prefix_digits": PAN_PREFIX_DIGIT_COUNT},
        "brands": brands,
        "ranges": [],
    });
    let mut table = BinTable::from_json(&serde_json::to_vec(&empty).unwrap()).unwrap();
    for (low, kind) in ranges {
        let b = &kind.bin;
        table
            .insert(Range {
                low,
                high: low + span - 1,
                attributes: Attributes {
                    country: b.country,
                    card_type: b.card_type,
                    brand: b.brand.to_owned(),
                    commercial: b.commercial,
                },
            })
            .unwrap();
    }
    String::from_utf8(table.to_json().unwrap()).unwrap()
}

fn luhn(digits: &str) -> String {
    let total: u32 = digits
        .chars()
        .rev()
        .enumerate()
        .map(|(i, c)| {
            let d = c.to_digit(DECIMAL_BASE).unwrap() * if i % 2 == 0 { 2 } else { 1 };
            if d >= DECIMAL_BASE { d - (DECIMAL_BASE - 1) } else { d }
        })
        .sum();
    let check = (DECIMAL_BASE - total % DECIMAL_BASE) % DECIMAL_BASE;
    format!("{digits}{check}")
}

/// `digits` in BCD, padded with `F` nibbles to `byte_len`.
fn padded_bcd(digits: &str, byte_len: usize) -> Vec<u8> {
    let nibbles: String = digits.chars().chain(iter::repeat(NIBBLE_PAD)).take(byte_len * NIBBLES_PER_BYTE).collect();
    const_hex::decode(nibbles).unwrap()
}

fn tlv(tag: &[u8], value: &[u8]) -> Vec<u8> {
    let length = if value.len() < usize::from(BER_LONG_LENGTH_FLAG) {
        vec![byte_len(value)]
    } else {
        vec![BER_ONE_LENGTH_BYTE, byte_len(value)]
    };
    [tag, &length, value].concat()
}

fn element(tag: &'static str, value: &[u8], source: &'static str) -> Element {
    Element {
        tag,
        value: const_hex::encode_upper(value),
        length: value.len(),
        source,
    }
}

fn byte_len(bytes: &[u8]) -> u8 {
    u8::try_from(bytes.len()).unwrap()
}

fn pretty<T: Serialize>(value: &T) -> String {
    serde_json::to_string_pretty(value).unwrap() + "\n"
}
