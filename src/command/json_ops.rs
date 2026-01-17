// src/command/json_ops.rs

use crate::error::{AppError, AppResult};
use crate::json_canon::hash_canonical_value_object;

use jsonschema::{Draft, JSONSchema};
use serde_json::Value;

const MAX_JSON_BYTES: usize = 1024 * 1024;
const MAX_SCHEMA_BYTES: usize = 1024 * 1024;

/// Backward-compatible entry point (matches existing callers)
pub fn canonicalize_json_2020_12(json_text: &str, schema_text: &str) -> AppResult<[u8; 32]> {
    validate_json_2020_12(json_text, schema_text)?;

    let instance: Value =
        serde_json::from_str(json_text).map_err(|e| AppError::InvalidJson(e.to_string()))?;

    hash_canonical_value_object(&instance)
}

pub fn validate_json_2020_12(json_text: &str, schema_text: &str) -> AppResult<()> {
    if json_text.len() > MAX_JSON_BYTES {
        return Err(AppError::JsonTooLarge);
    }
    if schema_text.len() > MAX_SCHEMA_BYTES {
        return Err(AppError::SchemaTooLarge);
    }

    let instance: Value =
        serde_json::from_str(json_text).map_err(|e| AppError::InvalidJson(e.to_string()))?;

    let schema_value: Value = serde_json::from_str(schema_text)
        .map_err(|e| AppError::InvalidSchemaJson(e.to_string()))?;

    if let Some(obj) = schema_value.as_object() {
        if let Some(v) = obj.get("$schema") {
            let s = v.as_str().unwrap_or("");
            if !s.contains("2020-12") {
                return Err(AppError::SchemaWrongDraft);
            }
        }
    }

    let compiled = JSONSchema::options()
        .with_draft(Draft::Draft202012)
        .compile(&schema_value)
        .map_err(|e| AppError::SchemaCompile(e.to_string()))?;

    let result = compiled.validate(&instance);

    match result {
        Ok(()) => Ok(()),
        Err(errs) => {
            let mut it = errs.into_iter();

            let mut shown = Vec::new();
            for _ in 0..8 {
                if let Some(e) = it.next() {
                    shown.push(e.to_string());
                } else {
                    break;
                }
            }

            let more = it.count();
            let mut summary = shown.join("; ");
            if more > 0 {
                summary.push_str(&format!(" … (+{more} more)"));
            }

            Err(AppError::SchemaValidation(summary))
        }
    }
}

pub fn canonicalize_json(json_text: &str) -> AppResult<[u8; 32]> {
    if json_text.len() > MAX_JSON_BYTES {
        return Err(AppError::JsonTooLarge);
    }

    let instance: Value =
        serde_json::from_str(json_text).map_err(|e| AppError::InvalidJson(e.to_string()))?;

    hash_canonical_value_object(&instance)
}

// ======================================================
// Unit Tests
// ======================================================

#[cfg(test)]
mod tests {
    use super::*;
    use crate::error::AppError;

    const SCHEMA_2020_12: &str = r#"{
      "$schema": "https://json-schema.org/draft/2020-12/schema",
      "type": "object",
      "additionalProperties": false,
      "required": ["name", "age", "active"],
      "properties": {
        "name":   { "type": "string" },
        "age":    { "type": "integer" },
        "active": { "type": "boolean" }
      }
    }"#;

    #[test]
    fn validate_json_2020_12_accepts_valid_instance() {
        let json_ok = r#"{"name":"Alice","age":30,"active":true}"#;
        validate_json_2020_12(json_ok, SCHEMA_2020_12).expect("should validate");
    }

    #[test]
    fn validate_json_2020_12_rejects_invalid_instance_with_schema_validation_error() {
        // missing required "age"
        let json_bad = r#"{"name":"Alice","active":true}"#;

        match validate_json_2020_12(json_bad, SCHEMA_2020_12) {
            Err(AppError::SchemaValidation(_)) => {}
            other => panic!("expected SchemaValidation(_), got: {:?}", other),
        }
    }

    #[test]
    fn validate_json_2020_12_rejects_wrong_draft_when_schema_declares_other() {
        let json_ok = r#"{"name":"Alice","age":30,"active":true}"#;

        let schema_wrong = r#"{
          "$schema": "https://json-schema.org/draft/2019-09/schema",
          "type": "object",
          "additionalProperties": false,
          "required": ["name", "age", "active"],
          "properties": {
            "name":   { "type": "string" },
            "age":    { "type": "integer" },
            "active": { "type": "boolean" }
          }
        }"#;

        match validate_json_2020_12(json_ok, schema_wrong) {
            Err(AppError::SchemaWrongDraft) => {}
            other => panic!("expected SchemaWrongDraft, got: {:?}", other),
        }
    }

    #[test]
    fn validate_json_2020_12_rejects_invalid_json() {
        let json_bad = r#"{"name":"Alice""#; // broken JSON
        match validate_json_2020_12(json_bad, SCHEMA_2020_12) {
            Err(AppError::InvalidJson(_)) => {}
            other => panic!("expected InvalidJson(_), got: {:?}", other),
        }
    }

    #[test]
    fn validate_json_2020_12_rejects_invalid_schema_json() {
        let json_ok = r#"{"name":"Alice","age":30,"active":true}"#;
        let schema_bad = r#"{"$schema":"https://json-schema.org/draft/2020-12/schema","#; // broken JSON
        match validate_json_2020_12(json_ok, schema_bad) {
            Err(AppError::InvalidSchemaJson(_)) => {}
            other => panic!("expected InvalidSchemaJson(_), got: {:?}", other),
        }
    }

    #[test]
    fn validate_json_2020_12_enforces_json_and_schema_size_limits() {
        let too_big_json = "x".repeat(MAX_JSON_BYTES + 1);
        match validate_json_2020_12(&too_big_json, SCHEMA_2020_12) {
            Err(AppError::JsonTooLarge) => {}
            other => panic!("expected JsonTooLarge, got: {:?}", other),
        }

        let json_ok = r#"{"name":"Alice","age":30,"active":true}"#;
        let too_big_schema = "x".repeat(MAX_SCHEMA_BYTES + 1);
        match validate_json_2020_12(json_ok, &too_big_schema) {
            Err(AppError::SchemaTooLarge) => {}
            other => panic!("expected SchemaTooLarge, got: {:?}", other),
        }
    }

    #[test]
    fn canonicalize_json_2020_12_is_order_invariant_for_objects() {
        let json_a = r#"{"name":"Alice","age":30,"active":true}"#;
        let json_b = r#"{"active":true,"age":30,"name":"Alice"}"#;

        let ha = canonicalize_json_2020_12(json_a, SCHEMA_2020_12).expect("canonicalize a");
        let hb = canonicalize_json_2020_12(json_b, SCHEMA_2020_12).expect("canonicalize b");

        assert_eq!(ha, hb);
    }

    #[test]
    fn canonicalize_json_matches_2020_12_when_schema_accepts() {
        let json = r#"{"name":"Alice","age":30,"active":true}"#;

        let h1 = canonicalize_json(json).expect("canonicalize_json");
        let h2 =
            canonicalize_json_2020_12(json, SCHEMA_2020_12).expect("canonicalize_json_2020_12");

        assert_eq!(h1, h2);
    }
}
