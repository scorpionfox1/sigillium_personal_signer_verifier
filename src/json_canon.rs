// src/json_canon.rs

use crate::error::{AppError, AppResult};
use sha2::{Digest, Sha256};
use std::io::Write;

use serde_json::Value;

pub fn hash_canonical_value(value: &Value) -> AppResult<[u8; 32]> {
    let mut hasher = Sha256::new();
    write_canonical_value(&mut hasher, value)?;
    let result = hasher.finalize();

    let mut out = [0u8; 32];
    out.copy_from_slice(&result[..]);
    Ok(out)
}

pub fn hash_canonical_value_object(value: &Value) -> AppResult<[u8; 32]> {
    let obj = value.as_object().ok_or(AppError::JsonNotObject)?;
    hash_canonical_value(&Value::Object(obj.clone()))
}

fn write_canonical_value<W: Write>(w: &mut W, value: &Value) -> AppResult<()> {
    match value {
        Value::Null => {
            w.write_all(b"null")?;
        }
        Value::Bool(b) => {
            if *b {
                w.write_all(b"true")?;
            } else {
                w.write_all(b"false")?;
            }
        }
        Value::Number(n) => {
            write!(w, "{}", n)?;
        }
        Value::String(s) => {
            serde_json::to_writer(&mut *w, s)
                .map_err(|e| AppError::JsonCanonicalize(e.to_string()))?;
        }
        Value::Array(arr) => {
            w.write_all(b"[")?;
            let mut first = true;
            for v in arr {
                if !first {
                    w.write_all(b",")?;
                }
                first = false;
                write_canonical_value(w, v)?;
            }
            w.write_all(b"]")?;
        }
        Value::Object(map) => {
            w.write_all(b"{")?;
            let mut keys: Vec<_> = map.keys().collect();
            keys.sort();

            let mut first = true;
            for k in keys {
                if !first {
                    w.write_all(b",")?;
                }
                first = false;

                serde_json::to_writer(&mut *w, k)
                    .map_err(|e| AppError::JsonCanonicalize(e.to_string()))?;
                w.write_all(b":")?;
                write_canonical_value(w, &map[k])?;
            }
            w.write_all(b"}")?;
        }
    }
    Ok(())
}

pub fn canonical_value_string(value: &Value) -> AppResult<String> {
    let mut out: Vec<u8> = Vec::new();
    write_canonical_value(&mut out, value)?;
    String::from_utf8(out).map_err(|_| AppError::JsonCanonicalize("canonical utf-8 failed".into()))
}

pub fn canonical_value_object_string(value: &Value) -> AppResult<String> {
    let obj = value.as_object().ok_or(AppError::JsonNotObject)?;
    canonical_value_string(&Value::Object(obj.clone()))
}

// ======================================================
// Unit Tests
// ======================================================

#[cfg(test)]
mod tests {
    use super::*;
    use crate::error::AppError;
    use serde_json::json;

    #[test]
    fn object_key_order_is_ignored() {
        let v1 = json!({"a": 1, "b": 2});
        let v2 = json!({"b": 2, "a": 1});

        let h1 = hash_canonical_value_object(&v1).unwrap();
        let h2 = hash_canonical_value_object(&v2).unwrap();

        assert_eq!(h1, h2);
    }

    #[test]
    fn array_order_is_respected() {
        let v1 = json!({"a": [1, 2]});
        let v2 = json!({"a": [2, 1]});

        let h1 = hash_canonical_value_object(&v1).unwrap();
        let h2 = hash_canonical_value_object(&v2).unwrap();

        assert_ne!(h1, h2);
    }

    #[test]
    fn numbers_are_syntax_sensitive_one_vs_one_point_zero() {
        let v1 = json!({"a": 1});
        let v2 = json!({"a": 1.0});

        let h1 = hash_canonical_value_object(&v1).unwrap();
        let h2 = hash_canonical_value_object(&v2).unwrap();

        assert_ne!(h1, h2);
    }

    #[test]
    fn string_escape_syntax_hashes_the_same_after_parsing() {
        // These two JSON texts parse to the same String value: "<"
        let v1: Value = serde_json::from_str(r#"{"s":"<"}"#).unwrap();
        let v2: Value = serde_json::from_str(r#"{"s":"\u003c"}"#).unwrap();

        let h1 = hash_canonical_value_object(&v1).unwrap();
        let h2 = hash_canonical_value_object(&v2).unwrap();

        assert_eq!(h1, h2);
    }

    #[test]
    fn generalized_hash_supports_non_object_top_level() {
        let v = json!([{"a": 1}, {"b": 2}, null, true, "x"]);
        let h1 = hash_canonical_value(&v).unwrap();
        let h2 = hash_canonical_value(&v).unwrap();
        assert_eq!(h1, h2);
    }

    #[test]
    fn object_only_hash_rejects_non_object() {
        let v = json!([1, 2, 3]);
        let err = hash_canonical_value_object(&v).unwrap_err();
        assert!(matches!(err, AppError::JsonNotObject));
    }
}
