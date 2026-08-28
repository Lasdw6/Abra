//! Canonical JSON: the byte-exact form of anything Abra hashes or signs.
//!
//! See `docs/SPEC.md` §1.5. Object keys are sorted by their UTF-8 bytes, there
//! is no insignificant whitespace, and absent optional fields are omitted
//! rather than emitted as `null` (that part is enforced by the `serde`
//! attributes on the types themselves).
//!
//! Key sorting is done explicitly here rather than relying on `serde_json`'s
//! map implementation, so that enabling `serde_json/preserve_order` anywhere in
//! a dependency graph cannot silently change our hashes.

use serde::Serialize;
use serde_json::Value;

use crate::error::Result;

/// Serialize `value` to its canonical JSON bytes.
pub fn to_vec<T: Serialize + ?Sized>(value: &T) -> Result<Vec<u8>> {
    let v = serde_json::to_value(value)?;
    let mut out = Vec::new();
    write_value(&v, &mut out)?;
    Ok(out)
}

/// Serialize `value` to its canonical JSON string.
pub fn to_string<T: Serialize + ?Sized>(value: &T) -> Result<String> {
    let bytes = to_vec(value)?;
    // `write_value` only ever emits valid UTF-8.
    Ok(String::from_utf8(bytes).expect("canonical json is utf-8"))
}

fn write_value(v: &Value, out: &mut Vec<u8>) -> Result<()> {
    match v {
        Value::Null => out.extend_from_slice(b"null"),
        Value::Bool(true) => out.extend_from_slice(b"true"),
        Value::Bool(false) => out.extend_from_slice(b"false"),
        Value::Number(n) => out.extend_from_slice(n.to_string().as_bytes()),
        Value::String(s) => write_string(s, out),
        Value::Array(items) => {
            out.push(b'[');
            for (i, item) in items.iter().enumerate() {
                if i > 0 {
                    out.push(b',');
                }
                write_value(item, out)?;
            }
            out.push(b']');
        }
        Value::Object(map) => {
            let mut keys: Vec<&String> = map.keys().collect();
            keys.sort_by(|a, b| a.as_bytes().cmp(b.as_bytes()));
            out.push(b'{');
            for (i, k) in keys.iter().enumerate() {
                if i > 0 {
                    out.push(b',');
                }
                write_string(k, out);
                out.push(b':');
                write_value(&map[k.as_str()], out)?;
            }
            out.push(b'}');
        }
    }
    Ok(())
}

fn write_string(s: &str, out: &mut Vec<u8>) {
    // Delegate escaping to serde_json so we match its (RFC 8259 compliant)
    // escaping rules exactly.
    let encoded = serde_json::to_string(s).expect("string serialization cannot fail");
    out.extend_from_slice(encoded.as_bytes());
}

#[cfg(test)]
mod tests {
    use super::*;
    use serde_json::json;

    #[test]
    fn sorts_object_keys_at_every_depth() {
        let v = json!({ "b": 1, "a": { "z": [1, 2], "y": "x" }, "A": true });
        assert_eq!(
            to_string(&v).unwrap(),
            r#"{"A":true,"a":{"y":"x","z":[1,2]},"b":1}"#
        );
    }

    #[test]
    fn preserves_array_order() {
        let v = json!(["c", "a", "b"]);
        assert_eq!(to_string(&v).unwrap(), r#"["c","a","b"]"#);
    }

    #[test]
    fn no_insignificant_whitespace() {
        let v = json!({ "a": [1, {"b": 2}] });
        let s = to_string(&v).unwrap();
        assert!(!s.contains(' '));
        assert_eq!(s, r#"{"a":[1,{"b":2}]}"#);
    }

    #[test]
    fn escapes_strings_and_handles_unicode() {
        let v = json!({ "k": "line\n\"quoted\" \u{1f680} \u{7}" });
        assert_eq!(
            to_string(&v).unwrap(),
            "{\"k\":\"line\\n\\\"quoted\\\" \u{1f680} \\u0007\"}"
        );
    }

    #[test]
    fn key_order_of_input_does_not_matter() {
        let a: Value = serde_json::from_str(r#"{"b":1,"a":2}"#).unwrap();
        let b: Value = serde_json::from_str(r#"{"a":2,"b":1}"#).unwrap();
        assert_eq!(to_vec(&a).unwrap(), to_vec(&b).unwrap());
    }

    #[test]
    fn integers_have_no_fraction_or_exponent() {
        let v = json!({ "n": 1756300000000u64, "z": 0 });
        assert_eq!(to_string(&v).unwrap(), r#"{"n":1756300000000,"z":0}"#);
    }
}
