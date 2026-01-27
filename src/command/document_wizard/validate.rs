// src/command/document_wizard/validate.rs

use crate::{
    command::document_wizard::{current_doc, WizardError, WizardState},
    template::doc_wizard::{InputSpec, InputType},
};
use serde_json::Value as JsonValue;
use std::collections::BTreeMap;

trait ValidationSink {
    fn missing_required(&mut self, spec: &InputSpec);
    fn value_error(&mut self, spec: &InputSpec, err: WizardError);

    fn stop_early(&self) -> bool;
}

struct DocSink {
    err: Option<WizardError>,
}

impl DocSink {
    fn new() -> Self {
        Self { err: None }
    }
}

impl ValidationSink for DocSink {
    fn missing_required(&mut self, spec: &InputSpec) {
        if self.err.is_some() {
            return;
        }
        self.err = Some(WizardError::InputProblem(format!(
            "missing required input: {}",
            spec.key
        )));
    }

    fn value_error(&mut self, _spec: &InputSpec, err: WizardError) {
        if self.err.is_some() {
            return;
        }
        self.err = Some(err);
    }

    fn stop_early(&self) -> bool {
        true
    }
}

struct SectionSink {
    errors: Vec<String>,
}

impl SectionSink {
    fn new() -> Self {
        Self { errors: Vec::new() }
    }
}

impl ValidationSink for SectionSink {
    fn missing_required(&mut self, spec: &InputSpec) {
        self.errors
            .push(format!("Missing required: {} ({})", spec.label, spec.key));
    }

    fn value_error(&mut self, spec: &InputSpec, err: WizardError) {
        self.errors
            .push(format!("{} ({}): {}", spec.label, spec.key, err));
    }

    fn stop_early(&self) -> bool {
        false
    }
}

fn validate_inputs_against_specs(
    inputs: &BTreeMap<String, JsonValue>,
    specs: &[InputSpec],
    sink: &mut impl ValidationSink,
) {
    for spec in specs {
        let key = spec.key.as_str();
        let v_opt = inputs.get(key);

        // Required check: treat missing OR null as missing.
        if spec.required {
            let missing = match v_opt {
                None => true,
                Some(v) => v.is_null(),
            };
            if missing {
                sink.missing_required(spec);
                if sink.stop_early() {
                    return;
                }
                continue;
            }
        }

        let Some(v) = v_opt else {
            continue; // optional + not provided
        };
        if v.is_null() {
            continue; // optional + null treated as not provided
        }

        if let Err(e) = validate_input_value(key, spec, v) {
            sink.value_error(spec, e);
            if sink.stop_early() {
                return;
            }
        }
    }
}

/// Validate inputs for the current document:
/// - required fields present and non-null (and non-empty for strings)
/// - type checks (string/enum/number/int/date/bool/json)
/// - validators: uuid / hex / regex / min_len / max_len / min / max
/// - json schema: validated (requires `jsonschema` crate to be present)
///
/// NOTE: This function intentionally treats failures as user-correctable input problems,
/// except when the template itself is inconsistent (e.g. missing enum choices), which
/// should already be caught by template structural validation.
pub fn validate_current_doc_inputs(state: &WizardState) -> Result<(), WizardError> {
    let d = current_doc(state)?;

    // Build key -> InputSpec map for this doc.
    let mut spec_map: BTreeMap<String, InputSpec> = BTreeMap::new();
    for s in d.sections.iter() {
        if let Some(specs) = &s.inputs_spec {
            for inp in specs.iter() {
                spec_map
                    .entry(inp.key.clone())
                    .or_insert_with(|| inp.clone());
            }
        }
    }

    let specs: Vec<InputSpec> = spec_map.values().cloned().collect();

    let mut sink = DocSink::new();
    validate_inputs_against_specs(&d.doc_inputs, &specs, &mut sink);

    match sink.err {
        Some(e) => Err(e),
        None => Ok(()),
    }
}

pub fn validate_current_section_inputs(
    wiz: &WizardState,
    specs: &[InputSpec],
) -> Result<(), String> {
    let d = current_doc(wiz).map_err(|e| e.to_string())?;

    let mut sink = SectionSink::new();
    validate_inputs_against_specs(&d.doc_inputs, specs, &mut sink);

    if sink.errors.is_empty() {
        Ok(())
    } else {
        Err(sink.errors.join("\n"))
    }
}

pub fn validate_input_value(key: &str, spec: &InputSpec, v: &JsonValue) -> Result<(), WizardError> {
    match spec.input_type {
        InputType::String => {
            let s = v
                .as_str()
                .ok_or_else(|| WizardError::InputProblem(format!("'{}' must be a string", key)))?;
            if spec.required && s.trim().is_empty() {
                return Err(WizardError::InputProblem(format!(
                    "'{}' may not be empty",
                    key
                )));
            }
            apply_validators_string(key, s, spec.validators.as_deref())?;
        }

        InputType::Enum => {
            let s = v.as_str().ok_or_else(|| {
                WizardError::InputProblem(format!("'{}' must be a string (enum)", key))
            })?;
            let choices = spec.choices.as_ref().ok_or_else(|| {
                WizardError::TemplateProblem(format!(
                    "template error: enum '{}' missing choices",
                    key
                ))
            })?;
            if !choices.iter().any(|c| c == s) {
                return Err(WizardError::InputProblem(format!(
                    "'{}' must be one of: {}",
                    key,
                    choices.join(", ")
                )));
            }
        }

        InputType::Number => {
            if !v.is_number() {
                return Err(WizardError::InputProblem(format!(
                    "'{}' must be a number",
                    key
                )));
            }
            apply_validators_number(key, v, spec.validators.as_deref())?;
        }

        InputType::Int => {
            let n = v.as_i64().ok_or_else(|| {
                WizardError::InputProblem(format!("'{}' must be an integer", key))
            })?;
            apply_validators_int(key, n, spec.validators.as_deref())?;
        }

        InputType::Date => {
            let s = v.as_str().ok_or_else(|| {
                WizardError::InputProblem(format!("'{}' must be a string date", key))
            })?;
            validate_date_yyyy_mm_dd(key, s)?;
        }

        InputType::Bool => {
            if v.as_bool().is_none() {
                return Err(WizardError::InputProblem(format!(
                    "'{}' must be a boolean",
                    key
                )));
            }
        }

        InputType::Json => {
            // Any JsonValue allowed; schema validates structure.
            let schema = spec.schema.as_ref().ok_or_else(|| {
                WizardError::TemplateProblem(format!(
                    "template error: json input '{}' missing schema",
                    key
                ))
            })?;
            validate_json_schema(key, schema, v)?;
        }
    }

    Ok(())
}

fn apply_validators_string(
    key: &str,
    s: &str,
    validators: Option<&[String]>,
) -> Result<(), WizardError> {
    let Some(vs) = validators else {
        return Ok(());
    };

    for rule in vs.iter() {
        if rule == "uuid" {
            if !is_uuid_like(s) {
                return Err(WizardError::InputProblem(format!(
                    "'{}' must be a UUID",
                    key
                )));
            }
        } else if rule == "hex" {
            if !is_hex(s) {
                return Err(WizardError::InputProblem(format!("'{}' must be hex", key)));
            }
        } else if let Some(pat) = rule.strip_prefix("regex:") {
            let re = regex::Regex::new(pat).map_err(|e| {
                WizardError::TemplateProblem(format!(
                    "template error: invalid regex for '{}': {}",
                    key, e
                ))
            })?;
            if !re.is_match(s) {
                return Err(WizardError::InputProblem(format!(
                    "'{}' does not match pattern",
                    key
                )));
            }
        } else if let Some(n) = rule.strip_prefix("min_len:") {
            let n = n.parse::<usize>().map_err(|_| {
                WizardError::TemplateProblem(format!(
                    "template error: invalid min_len rule for '{}': {}",
                    key, rule
                ))
            })?;
            if s.chars().count() < n {
                return Err(WizardError::InputProblem(format!(
                    "'{}' must be at least {} chars",
                    key, n
                )));
            }
        } else if let Some(n) = rule.strip_prefix("max_len:") {
            let n = n.parse::<usize>().map_err(|_| {
                WizardError::TemplateProblem(format!(
                    "template error: invalid max_len rule for '{}': {}",
                    key, rule
                ))
            })?;
            if s.chars().count() > n {
                return Err(WizardError::InputProblem(format!(
                    "'{}' must be at most {} chars",
                    key, n
                )));
            }
        }
    }

    Ok(())
}

fn apply_validators_number(
    key: &str,
    v: &JsonValue,
    validators: Option<&[String]>,
) -> Result<(), WizardError> {
    let Some(vs) = validators else {
        return Ok(());
    };

    let n = v
        .as_f64()
        .ok_or_else(|| WizardError::InputProblem(format!("'{}' must be a number", key)))?;

    for rule in vs.iter() {
        if rule.starts_with("min:") {
            let minv = rule
                .trim_start_matches("min:")
                .parse::<f64>()
                .map_err(|_| {
                    WizardError::TemplateProblem(format!(
                        "template error: invalid min rule for '{}': {}",
                        key, rule
                    ))
                })?;
            if n < minv {
                return Err(WizardError::InputProblem(format!(
                    "'{}' must be >= {}",
                    key, minv
                )));
            }
        } else if rule.starts_with("max:") {
            let maxv = rule
                .trim_start_matches("max:")
                .parse::<f64>()
                .map_err(|_| {
                    WizardError::TemplateProblem(format!(
                        "template error: invalid max rule for '{}': {}",
                        key, rule
                    ))
                })?;
            if n > maxv {
                return Err(WizardError::InputProblem(format!(
                    "'{}' must be <= {}",
                    key, maxv
                )));
            }
        }
    }

    Ok(())
}

fn apply_validators_int(
    key: &str,
    n: i64,
    validators: Option<&[String]>,
) -> Result<(), WizardError> {
    let Some(vs) = validators else {
        return Ok(());
    };

    for rule in vs.iter() {
        if rule.starts_with("min:") {
            let minv = rule
                .trim_start_matches("min:")
                .parse::<i64>()
                .map_err(|_| {
                    WizardError::TemplateProblem(format!(
                        "template error: invalid min rule for '{}': {}",
                        key, rule
                    ))
                })?;
            if n < minv {
                return Err(WizardError::InputProblem(format!(
                    "'{}' must be >= {}",
                    key, minv
                )));
            }
        } else if rule.starts_with("max:") {
            let maxv = rule
                .trim_start_matches("max:")
                .parse::<i64>()
                .map_err(|_| {
                    WizardError::TemplateProblem(format!(
                        "template error: invalid max rule for '{}': {}",
                        key, rule
                    ))
                })?;
            if n > maxv {
                return Err(WizardError::InputProblem(format!(
                    "'{}' must be <= {}",
                    key, maxv
                )));
            }
        }
    }

    Ok(())
}

fn validate_date_yyyy_mm_dd(key: &str, s: &str) -> Result<(), WizardError> {
    let parts: Vec<&str> = s.split('-').collect();
    if parts.len() != 3 {
        return Err(WizardError::InputProblem(format!(
            "'{}' must be in YYYY-MM-DD format",
            key
        )));
    }

    let year: i32 = parts[0].parse().map_err(|_| {
        WizardError::InputProblem(format!("'{}' must be in YYYY-MM-DD format", key))
    })?;
    let month: u32 = parts[1].parse().map_err(|_| {
        WizardError::InputProblem(format!("'{}' must be in YYYY-MM-DD format", key))
    })?;
    let day: u32 = parts[2].parse().map_err(|_| {
        WizardError::InputProblem(format!("'{}' must be in YYYY-MM-DD format", key))
    })?;

    if year <= 0 || month == 0 || month > 12 || day == 0 || day > 31 {
        return Err(WizardError::InputProblem(format!(
            "'{}' must be in YYYY-MM-DD format",
            key
        )));
    }

    Ok(())
}

fn validate_json_schema(
    key: &str,
    schema: &JsonValue,
    instance: &JsonValue,
) -> Result<(), WizardError> {
    // Uses the `jsonschema` crate.
    // Add dependency: `cargo add jsonschema`
    let compiled = jsonschema::JSONSchema::compile(schema).map_err(|e| {
        WizardError::TemplateProblem(format!(
            "template error: invalid JSON schema for '{}': {}",
            key, e
        ))
    })?;

    if let Err(errors) = compiled.validate(instance) {
        // Keep message concise but useful: first error.
        if let Some(first) = errors.into_iter().next() {
            return Err(WizardError::InputProblem(format!(
                "'{}' does not match schema: {}",
                key, first
            )));
        }
        return Err(WizardError::InputProblem(format!(
            "'{}' does not match schema",
            key
        )));
    }

    Ok(())
}

fn is_uuid_like(s: &str) -> bool {
    // 8-4-4-4-12 with hex chars.
    let parts: Vec<&str> = s.split('-').collect();
    if parts.len() != 5 {
        return false;
    }
    let lens = [8, 4, 4, 4, 12];
    for (p, &len) in parts.iter().zip(lens.iter()) {
        if p.len() != len || !is_hex(p) {
            return false;
        }
    }
    true
}

fn is_hex(s: &str) -> bool {
    !s.is_empty()
        && s.bytes()
            .all(|b| matches!(b, b'0'..=b'9' | b'a'..=b'f' | b'A'..=b'F'))
}

// ======================================================
// Unit Tests
// ======================================================

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn is_hex_accepts_lower_upper_and_digits() {
        assert!(is_hex("00"));
        assert!(is_hex("deadbeef"));
        assert!(is_hex("DEADBEEF"));
        assert!(is_hex("aBcD0123"));
    }

    #[test]
    fn is_hex_rejects_empty_and_non_hex() {
        assert!(!is_hex(""));
        assert!(!is_hex(" "));
        assert!(!is_hex("0xdeadbeef"));
        assert!(!is_hex("dead beef"));
        assert!(!is_hex("zz"));
        assert!(!is_hex("g0"));
    }

    #[test]
    fn is_uuid_like_accepts_standard_form() {
        assert!(is_uuid_like("00000000-0000-0000-0000-000000000000"));
        assert!(is_uuid_like("deadbeef-dead-beef-dead-beefdeadbeef"));
        assert!(is_uuid_like("DEADBEEF-DEAD-BEEF-DEAD-BEEFDEADBEEF"));
    }

    #[test]
    fn is_uuid_like_rejects_wrong_segments_or_lengths() {
        // Wrong segment count
        assert!(!is_uuid_like("00000000-0000-0000-0000"));
        assert!(!is_uuid_like("00000000-0000-0000-0000-000000000000-ffff"));

        // Wrong lengths
        assert!(!is_uuid_like("0000000-0000-0000-0000-000000000000"));
        assert!(!is_uuid_like("00000000-000-0000-0000-000000000000"));
        assert!(!is_uuid_like("00000000-0000-000-0000-000000000000"));
        assert!(!is_uuid_like("00000000-0000-0000-000-000000000000"));
        assert!(!is_uuid_like("00000000-0000-0000-0000-00000000000"));
    }

    #[test]
    fn is_uuid_like_rejects_non_hex_chars() {
        assert!(!is_uuid_like("zzzzzzzz-0000-0000-0000-000000000000"));
        assert!(!is_uuid_like("00000000-zzzz-0000-0000-000000000000"));
        assert!(!is_uuid_like("00000000-0000-zzzz-0000-000000000000"));
        assert!(!is_uuid_like("00000000-0000-0000-zzzz-000000000000"));
        assert!(!is_uuid_like("00000000-0000-0000-0000-zzzzzzzzzzzz"));
    }

    #[test]
    fn validate_date_accepts_basic_yyyy_mm_dd() {
        assert!(validate_date_yyyy_mm_dd("d", "2025-01-01").is_ok());
        assert!(validate_date_yyyy_mm_dd("d", "1999-12-31").is_ok());
    }

    #[test]
    fn validate_date_rejects_wrong_format_or_out_of_range() {
        // Wrong separators / parts
        assert!(validate_date_yyyy_mm_dd("d", "2025/01/01").is_err());
        assert!(validate_date_yyyy_mm_dd("d", "2025-01").is_err());
        assert!(validate_date_yyyy_mm_dd("d", "2025-01-01-00").is_err());
        assert!(validate_date_yyyy_mm_dd("d", "abcd-ef-gh").is_err());

        // Out of range
        assert!(validate_date_yyyy_mm_dd("d", "0000-01-01").is_err());
        assert!(validate_date_yyyy_mm_dd("d", "2025-00-01").is_err());
        assert!(validate_date_yyyy_mm_dd("d", "2025-13-01").is_err());
        assert!(validate_date_yyyy_mm_dd("d", "2025-01-00").is_err());
        assert!(validate_date_yyyy_mm_dd("d", "2025-01-32").is_err());
    }

    #[test]
    fn apply_validators_string_uuid_and_hex() {
        // uuid
        let err = apply_validators_string("id", "not-a-uuid", Some(&vec!["uuid".to_string()]))
            .unwrap_err();
        assert!(matches!(err, WizardError::InputProblem(_)));

        let ok = apply_validators_string(
            "id",
            "deadbeef-dead-beef-dead-beefdeadbeef",
            Some(&vec!["uuid".to_string()]),
        );
        assert!(ok.is_ok());

        // hex
        let err = apply_validators_string("h", "xyz", Some(&vec!["hex".to_string()])).unwrap_err();
        assert!(matches!(err, WizardError::InputProblem(_)));

        let ok = apply_validators_string("h", "DEADBEEF", Some(&vec!["hex".to_string()]));
        assert!(ok.is_ok());
    }

    #[test]
    fn apply_validators_string_min_max_len() {
        let err =
            apply_validators_string("x", "abc", Some(&vec!["min_len:4".to_string()])).unwrap_err();
        assert!(matches!(err, WizardError::InputProblem(_)));

        let err =
            apply_validators_string("x", "abcd", Some(&vec!["max_len:3".to_string()])).unwrap_err();
        assert!(matches!(err, WizardError::InputProblem(_)));

        let ok = apply_validators_string(
            "x",
            "abcd",
            Some(&vec!["min_len:4".to_string(), "max_len:4".to_string()]),
        );
        assert!(ok.is_ok());
    }

    #[test]
    fn apply_validators_string_regex() {
        let ok = apply_validators_string(
            "email",
            "a@b.com",
            Some(&vec!["regex:^.+@.+\\..+$".to_string()]),
        );
        assert!(ok.is_ok());

        let err = apply_validators_string(
            "email",
            "not-an-email",
            Some(&vec!["regex:^.+@.+\\..+$".to_string()]),
        )
        .unwrap_err();
        assert!(matches!(err, WizardError::InputProblem(_)));
    }

    #[test]
    fn apply_validators_string_invalid_regex_is_template_problem() {
        let err = apply_validators_string("x", "anything", Some(&vec!["regex:(".to_string()]))
            .unwrap_err();
        assert!(matches!(err, WizardError::TemplateProblem(_)));
    }

    #[test]
    fn apply_validators_number_min_max() {
        let v = JsonValue::from(9.0);
        let err = apply_validators_number("n", &v, Some(&vec!["min:10".to_string()])).unwrap_err();
        assert!(matches!(err, WizardError::InputProblem(_)));

        let v = JsonValue::from(11.0);
        let err = apply_validators_number("n", &v, Some(&vec!["max:10".to_string()])).unwrap_err();
        assert!(matches!(err, WizardError::InputProblem(_)));

        let v = JsonValue::from(10.0);
        let ok = apply_validators_number(
            "n",
            &v,
            Some(&vec!["min:10".to_string(), "max:10".to_string()]),
        );
        assert!(ok.is_ok());
    }

    #[test]
    fn apply_validators_int_min_max() {
        let err = apply_validators_int("i", 9, Some(&vec!["min:10".to_string()])).unwrap_err();
        assert!(matches!(err, WizardError::InputProblem(_)));

        let err = apply_validators_int("i", 11, Some(&vec!["max:10".to_string()])).unwrap_err();
        assert!(matches!(err, WizardError::InputProblem(_)));

        let ok = apply_validators_int(
            "i",
            10,
            Some(&vec!["min:10".to_string(), "max:10".to_string()]),
        );
        assert!(ok.is_ok());
    }

    #[test]
    fn apply_validators_bad_rules_are_template_problem() {
        let err = apply_validators_string("x", "abc", Some(&vec!["min_len:nope".to_string()]))
            .unwrap_err();
        assert!(matches!(err, WizardError::TemplateProblem(_)));

        let err = apply_validators_string("x", "abc", Some(&vec!["max_len:nope".to_string()]))
            .unwrap_err();
        assert!(matches!(err, WizardError::TemplateProblem(_)));

        let err = apply_validators_number(
            "n",
            &JsonValue::from(1.0),
            Some(&vec!["min:nope".to_string()]),
        )
        .unwrap_err();
        assert!(matches!(err, WizardError::TemplateProblem(_)));

        let err = apply_validators_int("i", 1, Some(&vec!["max:nope".to_string()])).unwrap_err();
        assert!(matches!(err, WizardError::TemplateProblem(_)));
    }
}
