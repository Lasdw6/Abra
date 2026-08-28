//! Abra-CJSON serialization and byte validation (SPEC §2).
use crate::{Error, Result};
use serde::{Deserialize, Serialize};
use serde_json::Value;

const MAX: i64 = 9_007_199_254_740_991;

/// Serialize a serde value as Abra-CJSON. Negative integers are accepted only
/// below top-level `payload` and `extensions`.
pub fn to_vec<T: Serialize + ?Sized>(value: &T) -> Result<Vec<u8>> {
    let value = serde_json::to_value(value)?;
    validate_value(&value)?;
    let mut out = Vec::new();
    write(&value, &mut out)?;
    Ok(out)
}

/// Serialize as an Abra-CJSON UTF-8 string.
pub fn to_string<T: Serialize + ?Sized>(value: &T) -> Result<String> {
    Ok(String::from_utf8(to_vec(value)?).expect("CJSON is UTF-8"))
}

/// Parse one value, validate schema-aware integer ranges, reserialize, and
/// reject unless the input bytes were already canonical (SPEC §2).
pub fn validate_canonical(bytes: &[u8]) -> Result<Value> {
    if bytes.starts_with(&[0xef, 0xbb, 0xbf]) {
        return Err(Error::invalid("JSON BOM"));
    }
    let mut de = serde_json::Deserializer::from_slice(bytes);
    let value = Value::deserialize(&mut de)?;
    de.end()?;
    validate_value(&value)?;
    let mut canonical = Vec::new();
    write(&value, &mut canonical)?;
    if canonical != bytes {
        return Err(Error::invalid("noncanonical Abra-CJSON bytes"));
    }
    Ok(value)
}

/// Validate the integer profile of an envelope-shaped JSON value.
pub fn validate_value(value: &Value) -> Result<()> {
    validate_at(value, false, 0)
}

fn validate_at(v: &Value, negatives: bool, depth: usize) -> Result<()> {
    match v {
        Value::Number(n) => {
            let i = n
                .as_i64()
                .ok_or_else(|| Error::invalid("numbers must be integers in the safe range"))?;
            if i > MAX || i < if negatives { -MAX } else { 0 } {
                return Err(Error::invalid("integer outside Abra-CJSON range"));
            }
        }
        Value::Array(a) => {
            for x in a {
                validate_at(x, negatives, depth + 1)?;
            }
        }
        Value::Object(m) => {
            for (k, x) in m {
                let slot = depth == 0 && (k == "payload" || k == "extensions");
                validate_at(x, negatives || slot, depth + 1)?;
            }
        }
        _ => {}
    }
    Ok(())
}

fn write(v: &Value, out: &mut Vec<u8>) -> Result<()> {
    match v {
        Value::Null => out.extend_from_slice(b"null"),
        Value::Bool(true) => out.extend_from_slice(b"true"),
        Value::Bool(false) => out.extend_from_slice(b"false"),
        Value::Number(n) => out.extend_from_slice(
            n.as_i64()
                .ok_or_else(|| Error::invalid("non-integer"))?
                .to_string()
                .as_bytes(),
        ),
        Value::String(s) => string(s, out),
        Value::Array(a) => {
            out.push(b'[');
            for (i, x) in a.iter().enumerate() {
                if i > 0 {
                    out.push(b',')
                }
                write(x, out)?;
            }
            out.push(b']');
        }
        Value::Object(m) => {
            let mut keys: Vec<_> = m.keys().collect();
            keys.sort_by(|a, b| a.as_bytes().cmp(b.as_bytes()));
            out.push(b'{');
            for (i, k) in keys.iter().enumerate() {
                if i > 0 {
                    out.push(b',')
                }
                string(k, out);
                out.push(b':');
                write(&m[*k], out)?;
            }
            out.push(b'}');
        }
    }
    Ok(())
}
fn string(s: &str, out: &mut Vec<u8>) {
    out.push(b'"');
    for c in s.chars() {
        match c {
            '"' => out.extend_from_slice(br#"\""#),
            '\\' => out.extend_from_slice(br#"\\"#),
            '\x08' => out.extend_from_slice(br"\b"),
            '\t' => out.extend_from_slice(br"\t"),
            '\n' => out.extend_from_slice(br"\n"),
            '\x0c' => out.extend_from_slice(br"\f"),
            '\r' => out.extend_from_slice(br"\r"),
            c if (c as u32) < 32 => {
                out.extend_from_slice(format!("\\u00{:02x}", c as u32).as_bytes())
            }
            c => {
                let mut b = [0; 4];
                out.extend_from_slice(c.encode_utf8(&mut b).as_bytes())
            }
        }
    }
    out.push(b'"')
}
