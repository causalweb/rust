use std::{collections::BTreeMap, fmt};

use serde::{
    Deserialize, Deserializer,
    de::{MapAccess, Visitor},
};
use serde_json::{Value, value::RawValue};

use crate::Error;

// Raw children preserve number spellings and escaped keys until duplicate checks finish.
struct UniqueObject(BTreeMap<String, Box<RawValue>>);

impl<'de> Deserialize<'de> for UniqueObject {
    fn deserialize<D: Deserializer<'de>>(d: D) -> Result<Self, D::Error> {
        struct ObjectVisitor;
        impl<'de> Visitor<'de> for ObjectVisitor {
            type Value = UniqueObject;
            fn expecting(&self, f: &mut fmt::Formatter) -> fmt::Result {
                f.write_str("an object with unique member names")
            }
            fn visit_map<M: MapAccess<'de>>(self, mut map: M) -> Result<Self::Value, M::Error> {
                let mut entries = BTreeMap::new();
                while let Some((key, value)) = map.next_entry::<String, Box<RawValue>>()? {
                    if entries.insert(key, value).is_some() {
                        return Err(serde::de::Error::custom("duplicate JSON member"));
                    }
                }
                Ok(UniqueObject(entries))
            }
        }
        d.deserialize_map(ObjectVisitor)
    }
}

fn unique(text: &str, depth: usize, max_depth: usize) -> Result<Value, Error> {
    if depth > max_depth {
        return Err(Error::InvalidEvidence);
    }
    let text = text.trim_matches([' ', '\t', '\r', '\n']);
    match text.as_bytes().first() {
        Some(b'{') => {
            let object: UniqueObject =
                serde_json::from_str(text).map_err(|_| Error::InvalidEvidence)?;
            object
                .0
                .into_iter()
                .map(|(key, raw)| Ok((key, unique(raw.get(), depth + 1, max_depth)?)))
                .collect::<Result<serde_json::Map<_, _>, Error>>()
                .map(Value::Object)
        }
        Some(b'[') => {
            let array: Vec<Box<RawValue>> =
                serde_json::from_str(text).map_err(|_| Error::InvalidEvidence)?;
            array
                .into_iter()
                .map(|raw| unique(raw.get(), depth + 1, max_depth))
                .collect::<Result<Vec<_>, _>>()
                .map(Value::Array)
        }
        _ => serde_json::from_str(text).map_err(|_| Error::InvalidEvidence),
    }
}

pub(crate) fn object(bytes: &[u8], max_depth: usize) -> Result<Value, Error> {
    let text = std::str::from_utf8(bytes).map_err(|_| Error::InvalidEvidence)?;
    if text.starts_with('\u{feff}') {
        return Err(Error::InvalidEvidence);
    }
    let value = unique(text, 1, max_depth)?;
    if !value.is_object() {
        return Err(Error::InvalidEvidence);
    }
    Ok(value)
}

pub(crate) fn string<'a>(value: &'a Value, key: &str) -> Result<&'a str, Error> {
    value
        .get(key)
        .and_then(Value::as_str)
        .filter(|v| !v.is_empty())
        .ok_or(Error::InvalidEvidence)
}

// NumericDate is mathematically integral: 1e2 and 100.0 are valid, 100.5 is not.
// Do not round through a binary float near the 2^53 boundary.
pub(crate) fn integer(value: &Value, maximum: u64) -> Result<u64, Error> {
    let number = value.as_number().ok_or(Error::InvalidEvidence)?.to_string();
    let (mantissa, exponent) = number.split_once(['e', 'E']).unwrap_or((&number, "0"));
    let negative = mantissa.starts_with('-');
    let mantissa = mantissa.trim_start_matches('-');
    let fraction = mantissa.split_once('.').map_or(0, |(_, part)| part.len());
    let digits: String = mantissa.chars().filter(|c| *c != '.').collect();
    let digits = digits.trim_start_matches('0');
    if digits.is_empty() {
        return Ok(0);
    }
    if negative {
        return Err(Error::InvalidEvidence);
    }
    let scale = exponent
        .parse::<i64>()
        .ok()
        .and_then(|n| n.checked_sub(fraction as i64))
        .ok_or(Error::InvalidEvidence)?;
    let integral = if scale >= 0 {
        if scale > 20 || digits.len() + scale as usize > 20 {
            return Err(Error::InvalidEvidence);
        }
        format!("{digits}{}", "0".repeat(scale as usize))
    } else {
        let removed = scale.unsigned_abs();
        if removed >= digits.len() as u64 {
            return Err(Error::InvalidEvidence);
        }
        let end = digits.len() - removed as usize;
        if !digits[end..].bytes().all(|b| b == b'0') {
            return Err(Error::InvalidEvidence);
        }
        digits[..end].to_owned()
    };
    integral
        .parse::<u64>()
        .ok()
        .filter(|n| *n <= maximum)
        .ok_or(Error::InvalidEvidence)
}
