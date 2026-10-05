use emv::{Attributes, BinTable, CardType, Error, Range};
use serde_json::{Value, json};

fn attributes(country: u16, card_type: CardType, brand: &str) -> Attributes {
    Attributes {
        country,
        card_type,
        brand: brand.to_owned(),
        commercial: false,
    }
}

fn range(low: u64, high: u64, brand: &str) -> Range {
    Range {
        low,
        high,
        attributes: attributes(208, CardType::Debit, brand),
    }
}

fn entry(slot: u64, low: u64, high: u64, brand: &str) -> Value {
    json!({"slot": slot, "low": low, "high": high, "country": 208, "type": "debit", "brand": brand, "commercial": false})
}

fn doc(ranges: &[Value]) -> Value {
    json!({
        "source": {"repository": "https://example.org/bins"},
        "tree": {"depth": 24, "prefix_digits": 12},
        "brands": ["VISA", "VISA/DANKORT"],
        "ranges": ranges,
    })
}

fn bytes(v: &Value) -> Vec<u8> {
    serde_json::to_vec(v).unwrap()
}

/// A 6-digit BIN split around an 8-digit one, and a gap before the next BIN.
fn small() -> BinTable {
    BinTable::from_json(&bytes(&doc(&[
        entry(0, 457_100_000_000, 457_100_399_999, "VISA/DANKORT"),
        entry(1, 457_100_400_000, 457_100_409_999, "VISA"),
        entry(2, 457_100_410_000, 457_100_999_999, "VISA/DANKORT"),
        entry(3, 457_102_000_000, 457_102_999_999, "VISA"),
    ])))
    .unwrap()
}

fn rejects(v: &Value) -> &'static str {
    match BinTable::from_json(&bytes(v)) {
        Err(Error::BinTable(reason)) => reason,
        other => panic!("accepted or failed otherwise: {other:?}"),
    }
}

#[test]
fn find_returns_the_range_holding_the_prefix() {
    let t = small();
    assert_eq!(t.find(457_100_000_000).map(|(s, _)| s), Some(0));
    assert_eq!(t.find(457_100_399_999).map(|(s, _)| s), Some(0));
    assert_eq!(t.find(457_100_400_000).map(|(s, r)| (s, r.attributes.brand.as_str())), Some((1, "VISA")));
    assert_eq!(t.find(457_100_999_999).map(|(s, _)| s), Some(2));
    assert_eq!(t.find(457_101_000_000), None, "gap between BINs");
    assert_eq!(t.find(457_099_999_999), None, "before the first range");
    assert_eq!(t.find(457_103_000_000), None, "after the last range");
}

#[test]
fn rejects_malformed_tables() {
    let ok = || doc(&[entry(0, 100, 199, "VISA"), entry(1, 200, 299, "VISA")]);
    assert!(BinTable::from_json(&bytes(&ok())).is_ok());

    let cases: Vec<(&str, Value)> = vec![
        ("overlap", doc(&[entry(0, 100, 200, "VISA"), entry(1, 200, 299, "VISA")])),
        ("same low", doc(&[entry(0, 100, 100, "VISA"), entry(1, 100, 100, "VISA")])),
        ("shared slot", doc(&[entry(0, 100, 199, "VISA"), entry(0, 200, 299, "VISA")])),
        ("unknown brand", doc(&[entry(0, 100, 199, "AMEX")])),
        ("low above high", doc(&[entry(0, 200, 100, "VISA")])),
        ("13-digit prefix", doc(&[entry(0, 100, 1_000_000_000_000, "VISA")])),
        ("slot out of the tree", doc(&[entry(1 << 24, 100, 199, "VISA")])),
    ];
    for (name, v) in &cases {
        assert!(matches!(BinTable::from_json(&bytes(v)), Err(Error::BinTable(_))), "{name}");
    }

    let mut v = ok();
    v["ranges"][0]["country"] = json!(0);
    rejects(&v);
    let mut v = ok();
    v["ranges"][0]["type"] = json!("charge");
    rejects(&v);
    let mut v = ok();
    v["tree"]["depth"] = json!(20);
    rejects(&v);
    let mut v = ok();
    v["tree"]["node"] = json!("SHA-256");
    rejects(&v);
    let mut v = ok();
    v["brands"] = json!(["VISA", "VISA"]);
    rejects(&v);
    let mut v = ok();
    v["tree"]["root"] = json!("00".repeat(32));
    assert_eq!(rejects(&v), "root differs from the ranges' tree");
}

#[test]
fn to_json_round_trips() {
    let t = small();
    let json = t.to_json().unwrap();
    let again = BinTable::from_json(&json).unwrap();
    assert_eq!(again.root(), t.root());
    assert_eq!(again.to_json().unwrap(), json);
    let v: Value = serde_json::from_slice(&json).unwrap();
    assert_eq!(v["source"]["repository"], "https://example.org/bins", "other keys are kept");
    assert_eq!(v["tree"]["root"], const_hex::encode(t.root().to_bytes()));
}

#[test]
fn changes_verify_and_match_a_rebuild() {
    let mut t = small();
    let rebuilt = |t: &BinTable| BinTable::from_json(&t.to_json().unwrap()).unwrap().root();

    let before = t.root();
    let change = t.insert(range(457_101_000_000, 457_101_999_999, "VISA")).unwrap();
    assert_eq!(change.slot(), 4);
    assert!(change.verify(before, t.root()));
    assert!(!change.verify(t.root(), before), "old and new swapped");
    assert_eq!(rebuilt(&t), t.root());

    let before = t.root();
    let mut moved = range(457_100_400_000, 457_100_409_999, "VISA");
    moved.attributes.card_type = CardType::Prepaid;
    let change = t.update(1, moved.clone()).unwrap();
    assert!(change.verify(before, t.root()));
    assert_eq!(t.get(1), Some(&moved));
    assert_eq!(rebuilt(&t), t.root());

    let before = t.root();
    let change = t.remove(0).unwrap();
    assert!(change.verify(before, t.root()));
    assert_eq!(t.get(0), None);
    assert_eq!(t.find(457_100_000_000), None);
    assert_eq!(rebuilt(&t), t.root());

    let change = t.insert(range(457_100_000_000, 457_100_099_999, "MASTERCARD")).unwrap();
    assert_eq!(change.slot(), 0, "the lowest empty slot is reused");
    let json: Value = serde_json::from_slice(&t.to_json().unwrap()).unwrap();
    assert_eq!(json["brands"][2], "MASTERCARD", "a new brand is appended");
    assert_eq!(rebuilt(&t), t.root());
}

#[test]
fn changes_keep_ranges_apart() {
    let mut t = small();
    let root = t.root();
    assert!(matches!(t.insert(range(457_100_399_999, 457_100_400_000, "VISA")), Err(Error::BinTable(_))));
    assert!(
        matches!(t.insert(range(457_099_000_000, 457_109_000_000, "VISA")), Err(Error::BinTable(_))),
        "covers several"
    );
    assert!(
        matches!(t.update(1, range(457_100_400_000, 457_100_410_000, "VISA")), Err(Error::BinTable(_))),
        "grows into slot 2"
    );
    assert!(matches!(t.update(9, range(1, 2, "VISA")), Err(Error::BinTable(_))), "empty slot");
    assert!(matches!(t.remove(9), Err(Error::BinTable(_))));
    assert_eq!(t.root(), root, "a rejected change changes nothing");

    t.update(1, range(457_100_400_001, 457_100_409_999, "VISA")).unwrap();
    assert_eq!(t.find(457_100_400_000), None, "shrinking a range opens a gap");
    t.insert(range(457_100_400_000, 457_100_400_000, "VISA")).unwrap();
}

#[test]
fn data_table_loads_and_matches_its_root() {
    let path = concat!(env!("CARGO_MANIFEST_DIR"), "/../data/bin-table.json");
    let json = std::fs::read(path).unwrap();
    let t = BinTable::from_json(&json).unwrap();
    let v: Value = serde_json::from_slice(&json).unwrap();
    assert!(v["tree"]["root"].is_string(), "the file gives its root");
    assert_eq!(t.to_json().unwrap(), json, "the file is in canonical form");

    let (_, parent) = t.find(457_100_000_000).unwrap();
    let (_, child) = t.find(457_100_400_000).unwrap();
    assert_eq!((parent.attributes.brand.as_str(), child.attributes.brand.as_str()), ("VISA/DANKORT", "VISA"));
    assert_eq!(child.attributes.country, 208);
}
