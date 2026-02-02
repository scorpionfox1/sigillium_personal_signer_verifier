// src/command/document_wizard/ops.rs

use crate::command::document_wizard::validate_input_value;
use crate::template::doc_wizard::{DocTemplate, HashAlgo, InputSpec};
use crate::template::doc_wizard_verify::{
    canonical_doc_text_from_sections, extract_input_tags, sha256_hex_of_text, validate_tag_coverage,
};
use crate::types::{TAG_ASSOC_KEY_ID, TAG_SIGNED_UTC};
use serde_json::{Map as JsonMap, Value as JsonValue};
use std::collections::{BTreeMap, BTreeSet};
use std::fs;
use std::path::Path;

use super::nav::current_doc_mut;
use super::types::{DocRunState, WizardError, WizardState};

pub fn load_wizard_from_path(path: impl AsRef<Path>) -> Result<WizardState, WizardError> {
    let s = fs::read_to_string(path)?;
    load_wizard_from_str(&s)
}

pub fn load_wizard_from_str(template_json5: &str) -> Result<WizardState, WizardError> {
    let template = crate::template::doc_wizard::parse_template_str(template_json5)?;
    let docs = template
        .docs
        .iter()
        .map(build_doc_run_state)
        .collect::<Vec<_>>();

    Ok(WizardState {
        template,
        docs,
        doc_index: 0,
    })
}

fn build_doc_run_state(doc: &DocTemplate) -> DocRunState {
    let canonical_text =
        canonical_doc_text_from_sections(doc.sections.iter().map(|s| s.text.as_str()));

    let computed_hash_hex = match doc.doc_hash.algo {
        HashAlgo::Sha256 => sha256_hex_of_text(&canonical_text),
    };

    let referenced_tags = extract_input_tags(&canonical_text);
    let (declared_inputs, input_spec_map, mut template_errors, template_warnings) =
        collect_declared_inputs(doc);

    // A) hash must match
    if !hex_eq_case_insensitive(&computed_hash_hex, &doc.doc_hash.hash) {
        template_errors.push(format!(
            "hash mismatch for doc '{}': expected {}, computed {}",
            doc.doc_identity.label, doc.doc_hash.hash, computed_hash_hex
        ));
    }

    // B) every [[tag]] in doc text must have a matching declared input key
    if let Err(e) = validate_tag_coverage(&referenced_tags, &declared_inputs) {
        template_errors.push(format!(
            "tag coverage failed for doc '{}': {}",
            doc.doc_identity.label, e
        ));
    }

    // Extra sanity: duplicate keys across sections are already treated as hard error in collect_declared_inputs.
    // Also: for enum/json types we already validated the template structurally in doc_wizard.rs.
    drop(input_spec_map); // kept here for future use (input validation); see validate_current_doc_inputs().

    DocRunState {
        doc_identity: doc.doc_identity.clone(),
        doc_about: doc.doc_about.clone(),
        sections: doc.sections.clone(),
        expected_hash_hex: doc.doc_hash.hash.clone(),
        computed_hash_hex,
        hash_algo: doc.doc_hash.algo,

        referenced_tags,
        declared_inputs,

        template_errors,
        template_warnings,

        doc_inputs: BTreeMap::new(),
    }
}

/// Collect inputs declared across all sections. Returns:
/// - declared_inputs set
/// - map of key -> InputSpec (first occurrence kept; duplicates cause hard error)
/// - template_errors
/// - template_warnings
fn collect_declared_inputs(
    doc: &DocTemplate,
) -> (
    BTreeSet<String>,
    BTreeMap<String, InputSpec>,
    Vec<String>,
    Vec<String>,
) {
    let mut declared = BTreeSet::new();
    let mut map = BTreeMap::new();
    let mut errs = Vec::new();
    let mut warns = Vec::new();

    for (si, s) in doc.sections.iter().enumerate() {
        if let Some(specs) = &s.inputs_spec {
            for (ii, inp) in specs.iter().enumerate() {
                let key = inp.key.trim().to_string();
                if key.is_empty() {
                    errs.push(format!(
                        "doc '{}' section[{}] inputs_spec[{}] has empty key",
                        doc.doc_identity.label, si, ii
                    ));
                    continue;
                }

                if map.contains_key(&key) {
                    errs.push(format!(
                        "doc '{}' declares duplicate input key '{}' across sections",
                        doc.doc_identity.label, key
                    ));
                    continue;
                }

                // Mild warning: if key contains characters not in our tag strict key set,
                // tags will never match it (since tags are [[A-Za-z0-9_]+]).
                if !key
                    .bytes()
                    .all(|b| matches!(b, b'a'..=b'z' | b'A'..=b'Z' | b'0'..=b'9' | b'_'))
                {
                    warns.push(format!(
                        "doc '{}' input key '{}' contains non [A-Za-z0-9_] characters; tags like [[{}]] will not match",
                        doc.doc_identity.label, key, key
                    ));
                }

                declared.insert(key.clone());
                map.insert(key, inp.clone());
            }
        }
    }

    (declared, map, errs, warns)
}

/// Set an input value for the current document.
/// UI can call this whenever a field changes.
///
/// For type=json, pass a JsonValue directly (preferred) or use `set_input_json_from_str`.
pub fn set_input_value_current_doc(
    state: &mut WizardState,
    key: &str,
    value: JsonValue,
) -> Result<(), WizardError> {
    let d = current_doc_mut(state)?;
    let k = key.trim();
    if k.is_empty() {
        return Err(WizardError::InputProblem("input key is empty".to_string()));
    }
    d.doc_inputs.insert(k.to_string(), value);
    Ok(())
}

/// Convenience for json inputs: parse a JSON string into a JsonValue and set it.
pub fn set_input_json_from_str_current_doc(
    state: &mut WizardState,
    key: &str,
    json_str: &str,
) -> Result<(), WizardError> {
    let v: JsonValue = serde_json::from_str(json_str).map_err(|e| {
        WizardError::InputProblem(format!("invalid JSON for '{}': {}", key.trim(), e))
    })?;
    set_input_value_current_doc(state, key, v)
}

pub fn build_json_bundle(state: &WizardState) -> Result<JsonValue, WizardError> {
    // Ensure everything is valid before building.
    for (i, d) in state.docs.iter().enumerate() {
        if !d.template_errors.is_empty() {
            return Err(WizardError::TemplateProblem(format!(
                "cannot build bundle: doc[{}] '{}' has template errors: {}",
                i,
                d.doc_identity.label,
                d.template_errors.join(" | ")
            )));
        }
    }

    // Validate all docs' inputs (not just current).
    for (i, _) in state.docs.iter().enumerate() {
        validate_doc_inputs_by_index(state, i)?;
    }

    let mut docs_json: Vec<JsonValue> = Vec::with_capacity(state.docs.len());

    for d in state.docs.iter() {
        let mut doc_obj = JsonMap::new();

        doc_obj.insert(
            "doc_identity".to_string(),
            serde_json::to_value(&d.doc_identity).expect("doc_identity to_value"),
        );

        let mut hash_obj = JsonMap::new();
        hash_obj.insert(
            "hash".to_string(),
            JsonValue::String(d.expected_hash_hex.clone()),
        );
        hash_obj.insert(
            "algo".to_string(),
            JsonValue::String(match d.hash_algo {
                HashAlgo::Sha256 => "sha256".to_string(),
            }),
        );
        doc_obj.insert("doc_hash".to_string(), JsonValue::Object(hash_obj));

        let mut inputs_obj = JsonMap::new();
        for (k, v) in d.doc_inputs.iter() {
            inputs_obj.insert(k.clone(), v.clone());
        }
        doc_obj.insert("doc_inputs".to_string(), JsonValue::Object(inputs_obj));

        docs_json.push(JsonValue::Object(doc_obj));
    }

    let mut bundle = JsonMap::new();
    bundle.insert(
        "signed_utc".to_string(),
        JsonValue::String(TAG_SIGNED_UTC.to_string()),
    );
    bundle.insert(
        "canonical_id".to_string(),
        JsonValue::String(TAG_ASSOC_KEY_ID.to_string()),
    );
    bundle.insert("docs".to_string(), JsonValue::Array(docs_json));

    Ok(JsonValue::Object(bundle))
}

fn validate_doc_inputs_by_index(state: &WizardState, idx: usize) -> Result<(), WizardError> {
    let d = state
        .docs
        .get(idx)
        .ok_or_else(|| WizardError::InvalidState("doc index out of range".to_string()))?;

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

    for (key, spec) in spec_map.iter() {
        let v_opt = d.doc_inputs.get(key);
        if spec.required {
            if v_opt.is_none() {
                return Err(WizardError::InputProblem(format!(
                    "doc '{}' missing required input: {}",
                    d.doc_identity.label, key
                )));
            }
        }
        let Some(v) = v_opt else {
            continue;
        };
        validate_input_value(key, spec, v)?;
    }

    Ok(())
}

fn hex_eq_case_insensitive(a: &str, b: &str) -> bool {
    if a.len() != b.len() {
        return false;
    }
    a.bytes()
        .zip(b.bytes())
        .all(|(x, y)| x.to_ascii_lowercase() == y.to_ascii_lowercase())
}

// ======================================================
// Unit Tests
// ======================================================

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn load_and_build_bundle_smoke() {
        // IMPORTANT: tags are [[key]] and hash must match canonical_doc_text_from_sections().
        let section_text = "Hello [[name]].";

        let canonical = canonical_doc_text_from_sections([section_text].into_iter());
        let hash = sha256_hex_of_text(&canonical);

        let tpl = format!(
            r#"
            {{
              template_id: "t1",
              docs: [
                {{
                  doc_identity: {{ id: "d1", label: "Doc 1", ver: "v1.0" }},
                  doc_hash: {{ algo: "sha256", hash: "{hash}" }},
                  sections: [
                    {{
                      section_id: "s1",
                      text: "{section_text}",
                      inputs_spec: [
                        {{ key: "name", label: "Name", type: "string", required: true }}
                      ]
                    }}
                  ]
                }}
              ]
            }}
            "#
        );

        let mut state = load_wizard_from_str(&tpl).unwrap();

        // Input type is string, so JSON string value is correct:
        set_input_json_from_str_current_doc(&mut state, "name", "\"World\"").unwrap();

        let bundle = build_json_bundle(&state).unwrap();
        let docs = bundle["docs"].as_array().expect("docs array");
        assert_eq!(docs.len(), 1);

        let doc0 = docs[0].as_object().expect("doc0 object");
        let inputs = doc0
            .get("doc_inputs")
            .and_then(|v| v.as_object())
            .expect("doc_inputs object");

        assert_eq!(inputs.get("name").unwrap(), "World");
    }

    #[test]
    fn hex_eq_case_insensitive_matches_equal_hex() {
        assert!(hex_eq_case_insensitive("deadbeef", "deadbeef"));
        assert!(hex_eq_case_insensitive("deadbeef", "DEADBEEF"));
        assert!(hex_eq_case_insensitive("DEADBEEF", "deadbeef"));
        assert!(hex_eq_case_insensitive("AaBbCc", "aabbcc"));
    }

    #[test]
    fn hex_eq_case_insensitive_rejects_length_or_mismatch() {
        assert!(!hex_eq_case_insensitive("a", "aa"));
        assert!(!hex_eq_case_insensitive("deadbeef", "deadbeee"));
        assert!(!hex_eq_case_insensitive("DEADBEEF", "DEADBEF0"));
    }
}
