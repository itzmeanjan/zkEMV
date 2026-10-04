use std::collections::{BTreeMap, BTreeSet, HashMap};

use ark_bn254::Fr;
use ark_ff::Zero;
use serde_json::{Value, json};

use super::{
    Attributes, BinTable, CardType, MAX_BRAND_COUNT, PAN_PREFIX_DIGIT_COUNT, Range, SLOT_COUNT, leaf,
    tree::{TREE_DEPTH, Tree},
    validate,
};
use crate::{Error, Result};

const LEAF: &str = "low + high·2^40 + country·2^80 + type·2^90 + brand·2^92 + commercial·2^100 + 2^101; 0 if empty. type: credit 1, debit 2, prepaid 3.";
const NODE: &str = "Poseidon2 (noir-lang/poseidon v0.3.0, t = 4) of the left and right child.";
const HEADER_ORDER: [&str; 3] = ["source", "license", "fields"];

impl BinTable {
    /// Parses `data/bin-table.json`'s format. A given root must match; other top-level keys are kept.
    ///
    /// # Errors
    ///
    /// [`Error::BinTable`]: malformed, invalid or overlapping ranges, another tree format, or a wrong root.
    pub fn from_json(json: &[u8]) -> Result<Self> {
        let Ok(Value::Object(mut other_keys)) = serde_json::from_slice(json) else {
            return Err(Error::BinTable("not a JSON object"));
        };
        let tree = other_keys.remove("tree").ok_or(Error::BinTable("no tree"))?;
        check_tree(&tree)?;
        let brands = parse_brands(other_keys.remove("brands").as_ref())?;
        let codes: HashMap<&str, u64> = brands.iter().map(String::as_str).zip(1..).collect();

        let mut slots: Vec<Option<Range>> = Vec::new();
        let entries = other_keys.remove("ranges");
        for entry in entries.as_ref().and_then(Value::as_array).ok_or(Error::BinTable("no ranges array"))? {
            let (slot, range) = parse_range(entry)?;
            if !codes.contains_key(range.attributes.brand.as_str()) {
                return Err(Error::BinTable("brand not in the brand list"));
            }
            if slots.len() <= slot {
                slots.resize(slot.saturating_add(1), None);
            }
            match slots.get_mut(slot) {
                Some(s @ None) => *s = Some(range),
                _ => return Err(Error::BinTable("two ranges share a slot")),
            }
        }

        let by_low: BTreeMap<u64, usize> = slots.iter().enumerate().filter_map(|(slot, r)| r.as_ref().map(|r| (r.low, slot))).collect();
        let sorted: Vec<&Range> = by_low.values().filter_map(|&slot| slots.get(slot).and_then(Option::as_ref)).collect();
        if by_low.len() != slots.iter().flatten().count() || sorted.windows(2).any(|w| matches!(w, [a, b] if a.high >= b.low)) {
            return Err(Error::BinTable("ranges overlap"));
        }

        let leaves = slots
            .iter()
            .map(|r| match r {
                Some(r) => codes.get(r.attributes.brand.as_str()).map_or_else(Fr::zero, |&code| leaf(r, code)),
                None => Fr::zero(),
            })
            .collect();
        let free: BTreeSet<usize> = slots.iter().enumerate().filter(|(_, r)| r.is_none()).map(|(slot, _)| slot).collect();
        let table = Self {
            other_keys,
            brands,
            slots,
            by_low,
            free,
            tree: Tree::new(leaves),
        };

        if let Some(root) = tree.get("root") {
            let given = root
                .as_str()
                .and_then(|s| const_hex::decode(s).ok())
                .ok_or(Error::BinTable("root is not hex"))?;
            if given != table.root().to_bytes() {
                return Err(Error::BinTable("root differs from the ranges' tree"));
            }
        }
        Ok(table)
    }

    /// [`BinTable::from_json`]'s format, with the root, one range per line.
    ///
    /// # Errors
    ///
    /// [`Error::BinTable`]: a kept key can't be serialized.
    pub fn to_json(&self) -> Result<Vec<u8>> {
        let first = HEADER_ORDER.iter().filter_map(|&key| self.other_keys.get_key_value(key));
        let rest = self.other_keys.iter().filter(|(key, _)| !HEADER_ORDER.contains(&key.as_str()));
        let tree = json!({
            "depth": TREE_DEPTH,
            "prefix_digits": PAN_PREFIX_DIGIT_COUNT,
            "leaf": LEAF,
            "node": NODE,
            "root": const_hex::encode(self.root().to_bytes()),
        });
        let brands = Value::from(self.brands.clone());

        let mut out = String::from("{\n");
        for (key, value) in first.chain(rest).chain([(&"tree".to_owned(), &tree), (&"brands".to_owned(), &brands)]) {
            out.push_str(&top_level_member(key, value)?);
            out.push_str(",\n");
        }
        let lines = self
            .slots
            .iter()
            .enumerate()
            .filter_map(|(slot, r)| r.as_ref().map(|r| range_line(slot, r)))
            .collect::<Result<Vec<_>>>()?;
        out.push_str("  \"ranges\": [\n");
        out.push_str(&lines.join(",\n"));
        out.push_str("\n  ]\n}\n");
        Ok(out.into_bytes())
    }
}

fn check_tree(tree: &Value) -> Result<()> {
    let depth = tree.get("depth").and_then(Value::as_u64).and_then(|d| usize::try_from(d).ok());
    let digits = tree.get("prefix_digits").and_then(Value::as_u64).and_then(|d| usize::try_from(d).ok());
    if depth != Some(TREE_DEPTH) || digits != Some(PAN_PREFIX_DIGIT_COUNT) {
        return Err(Error::BinTable("tree depth or prefix digits are not this crate's"));
    }
    for (key, expected) in [("leaf", LEAF), ("node", NODE)] {
        if tree.get(key).is_some_and(|v| v.as_str() != Some(expected)) {
            return Err(Error::BinTable("tree leaf or node is not this crate's"));
        }
    }
    Ok(())
}

fn parse_brands(brands: Option<&Value>) -> Result<Vec<String>> {
    let brands: Vec<String> = brands
        .and_then(Value::as_array)
        .ok_or(Error::BinTable("no brands array"))?
        .iter()
        .map(|b| {
            b.as_str()
                .filter(|b| !b.is_empty())
                .map(str::to_owned)
                .ok_or(Error::BinTable("brand is not a non-empty string"))
        })
        .collect::<Result<_>>()?;
    if brands.len() > MAX_BRAND_COUNT {
        return Err(Error::BinTable("more than 255 brands"));
    }
    if brands.iter().collect::<BTreeSet<_>>().len() != brands.len() {
        return Err(Error::BinTable("a brand is listed twice"));
    }
    Ok(brands)
}

fn parse_range(entry: &Value) -> Result<(usize, Range)> {
    let uint = |key: &str| {
        entry
            .get(key)
            .and_then(Value::as_u64)
            .ok_or(Error::BinTable("range field missing or not an integer"))
    };
    let slot = usize::try_from(uint("slot")?)
        .ok()
        .filter(|&s| s < SLOT_COUNT)
        .ok_or(Error::BinTable("slot out of the tree"))?;
    let country = u16::try_from(uint("country")?).map_err(|_| Error::BinTable("country must be an ISO 3166-1 numeric code"))?;
    let card_type = entry
        .get("type")
        .and_then(Value::as_str)
        .and_then(CardType::from_name)
        .ok_or(Error::BinTable("type must be credit, debit or prepaid"))?;
    let brand = entry.get("brand").and_then(Value::as_str).ok_or(Error::BinTable("brand missing"))?;
    let commercial = entry
        .get("commercial")
        .and_then(Value::as_bool)
        .ok_or(Error::BinTable("commercial must be a boolean"))?;
    let range = Range {
        low: uint("low")?,
        high: uint("high")?,
        attributes: Attributes {
            country,
            card_type,
            brand: brand.to_owned(),
            commercial,
        },
    };
    validate(&range)?;
    Ok((slot, range))
}

fn top_level_member(key: &str, value: &Value) -> Result<String> {
    let key = serde_json::to_string(key).map_err(|_| Error::BinTable("key can't be written"))?;
    let value = serde_json::to_string_pretty(value).map_err(|_| Error::BinTable("value can't be written"))?;
    Ok(format!("  {key}: {}", value.replace('\n', "\n  ")))
}

fn range_line(slot: usize, r: &Range) -> Result<String> {
    let a = &r.attributes;
    let brand = serde_json::to_string(&a.brand).map_err(|_| Error::BinTable("brand can't be written"))?;
    Ok(format!(
        "    {{\"slot\": {slot}, \"low\": {}, \"high\": {}, \"country\": {}, \"type\": \"{}\", \"brand\": {brand}, \"commercial\": {}}}",
        r.low,
        r.high,
        a.country,
        a.card_type.name(),
        a.commercial
    ))
}
