// src/template/doc_wizard.rs

use serde::{Deserialize, Serialize};
use serde_json::Value as JsonValue;
use std::collections::BTreeSet;
use std::fs;
use std::path::Path;

/// Top-level JSON5 template for the document wizard.
#[derive(Debug, Clone, Deserialize)]
pub struct BundleTemplate {
    pub template_id: Option<String>,
    pub template_desc: Option<String>,
    pub docs: Vec<DocTemplate>,
}

#[derive(Debug, Clone, Deserialize)]
pub struct DocTemplate {
    pub doc_identity: DocIdentity,
    pub doc_hash: DocHash,

    /// Optional UI-only intro shown in the wizard. Not part of signed material.
    pub doc_about: Option<String>,

    pub sections: Vec<SectionTemplate>,
}

#[derive(Debug, Clone, Deserialize, Serialize)]
pub struct DocIdentity {
    pub id: String,
    pub label: String,
    pub ver: String,
}

#[derive(Debug, Clone, Deserialize)]
pub struct DocHash {
    pub algo: HashAlgo,
    pub hash: String, // hex
}

#[derive(Debug, Clone, Copy, Deserialize)]
#[serde(rename_all = "lowercase")]
pub enum HashAlgo {
    Sha256,
}

#[derive(Debug, Clone, Deserialize)]
pub struct SectionTemplate {
    pub section_id: String,
    pub title: Option<String>,
    pub text: String,
    pub translation: Option<Translation>,
    pub inputs_spec: Option<Vec<InputSpec>>,
}

#[derive(Debug, Clone, Deserialize)]
pub struct Translation {
    pub lang: String,
    pub text: String,
}

#[derive(Debug, Clone, Deserialize)]
pub struct InputSpec {
    pub key: String,
    pub label: String,
    #[serde(rename = "type")]
    pub input_type: InputType,
    pub required: bool,

    /// for data type and property validators
    pub validators: Option<Vec<String>>,

    /// For enum inputs.
    pub choices: Option<Vec<String>>,

    /// For json inputs.
    /// Embedded JSON Schema object.
    pub schema: Option<JsonValue>,
    pub sample_json: Option<JsonValue>,
}

#[derive(Debug, Clone, Copy, Deserialize)]
#[serde(rename_all = "lowercase")]
pub enum InputType {
    String,
    Enum,
    Number,
    Int,
    Date,
    Bool,
    Json,
}

#[derive(Debug)]
pub enum TemplateLoadError {
    Io(std::io::Error),
    Parse(json5::Error),
    Validation(String),
}

impl std::fmt::Display for TemplateLoadError {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            TemplateLoadError::Io(e) => write!(f, "I/O error: {e}"),
            TemplateLoadError::Parse(e) => write!(f, "Template parse error: {e}"),
            TemplateLoadError::Validation(msg) => write!(f, "Template validation error: {msg}"),
        }
    }
}

impl std::error::Error for TemplateLoadError {}

impl From<std::io::Error> for TemplateLoadError {
    fn from(e: std::io::Error) -> Self {
        TemplateLoadError::Io(e)
    }
}

impl From<json5::Error> for TemplateLoadError {
    fn from(e: json5::Error) -> Self {
        TemplateLoadError::Parse(e)
    }
}

/// Parse a JSON5 template string.
pub fn parse_template_str(s: &str) -> Result<BundleTemplate, TemplateLoadError> {
    let tpl: BundleTemplate = json5::from_str(s)?;
    validate_template(&tpl)?;
    Ok(tpl)
}

/// Load a JSON5 template from disk.
pub fn load_template_path(path: impl AsRef<Path>) -> Result<BundleTemplate, TemplateLoadError> {
    let s = fs::read_to_string(path)?;
    parse_template_str(&s)
}

/// Minimal structural validation (no hashing or tag checks here).
pub fn validate_template(tpl: &BundleTemplate) -> Result<(), TemplateLoadError> {
    if tpl.docs.is_empty() {
        return Err(TemplateLoadError::Validation(
            "template must contain at least one document".to_string(),
        ));
    }

    let mut doc_labels = BTreeSet::new();
    for (i, d) in tpl.docs.iter().enumerate() {
        if d.doc_identity.id.trim().is_empty() {
            return Err(TemplateLoadError::Validation(format!(
                "docs[{i}].doc_identity.id must be non-empty"
            )));
        }
        if d.doc_identity.label.trim().is_empty() {
            return Err(TemplateLoadError::Validation(format!(
                "docs[{i}].doc_identity.label must be non-empty"
            )));
        }
        if !doc_labels.insert(d.doc_identity.label.trim().to_string()) {
            return Err(TemplateLoadError::Validation(format!(
                "docs[{i}].doc_identity.label must be unique; duplicate found for '{}'",
                d.doc_identity.label
            )));
        }
        if d.doc_identity.ver.trim().is_empty() {
            return Err(TemplateLoadError::Validation(format!(
                "docs[{i}].doc_identity.ver must be non-empty"
            )));
        }

        if d.sections.is_empty() {
            return Err(TemplateLoadError::Validation(format!(
                "docs[{i}] must contain at least one section"
            )));
        }

        for (j, s) in d.sections.iter().enumerate() {
            if s.section_id.trim().is_empty() {
                return Err(TemplateLoadError::Validation(format!(
                    "docs[{i}].sections[{j}].section_id must be non-empty"
                )));
            }
            if s.text.trim().is_empty() {
                return Err(TemplateLoadError::Validation(format!(
                    "docs[{i}].sections[{j}].text must be non-empty"
                )));
            }

            if let Some(inputs) = &s.inputs_spec {
                for (k, inp) in inputs.iter().enumerate() {
                    if inp.key.trim().is_empty() {
                        return Err(TemplateLoadError::Validation(format!(
                            "docs[{i}].sections[{j}].inputs_spec[{k}].key must be non-empty"
                        )));
                    }
                    if inp.label.trim().is_empty() {
                        return Err(TemplateLoadError::Validation(format!(
                            "docs[{i}].sections[{j}].inputs_spec[{k}].label must be non-empty"
                        )));
                    }

                    // Enum sanity
                    if matches!(inp.input_type, InputType::Enum) {
                        let choices = inp.choices.as_ref().ok_or_else(|| {
                            TemplateLoadError::Validation(format!(
                                "docs[{i}].sections[{j}].inputs_spec[{k}] type=enum requires choices"
                            ))
                        })?;

                        if choices.is_empty() {
                            return Err(TemplateLoadError::Validation(format!(
                                "docs[{i}].sections[{j}].inputs_spec[{k}] enum choices must be non-empty"
                            )));
                        }
                    }

                    // Json sanity
                    if matches!(inp.input_type, InputType::Json) && inp.schema.is_none() {
                        return Err(TemplateLoadError::Validation(format!(
                            "docs[{i}].sections[{j}].inputs_spec[{k}] type=json requires schema"
                        )));
                    }
                }
            }
        }
    }

    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn parses_minimal_template() {
        let s = r#"
        {
          template_id: "t1",
          docs: [
            {
              doc_identity: { id: "d1", label: "Doc 1", ver: "v1.0" },
              doc_hash: { algo: "sha256", hash: "00" },
              sections: [
                { section_id: "s1", text: "Hello." }
              ]
            }
          ]
        }
        "#;

        let tpl = parse_template_str(s).expect("parse ok");
        assert_eq!(tpl.docs.len(), 1);
        assert_eq!(tpl.docs[0].sections.len(), 1);
    }

    #[test]
    fn rejects_zero_sections() {
        let s = r#"
        {
          docs: [
            {
              doc_identity: { id: "d1", label: "Doc 1", ver: "v1.0" },
              doc_hash: { algo: "sha256", hash: "00" },
              sections: [ ]
            }
          ]
        }
        "#;

        let err = parse_template_str(s).unwrap_err();
        match err {
            TemplateLoadError::Validation(msg) => assert!(msg.contains("at least one section")),
            _ => panic!("expected validation error"),
        }
    }

    #[test]
    fn rejects_enum_without_choices() {
        let s = r#"
        {
          docs: [
            {
              doc_identity: { id: "d1", label: "Doc 1", ver: "v1.0" },
              doc_hash: { algo: "sha256", hash: "00" },
              sections: [
                {
                  section_id: "s1",
                  text: "Hello.",
                  inputs_spec: [
                    { key: "role", label: "Role", type: "enum", required: true }
                  ]
                }
              ]
            }
          ]
        }
        "#;

        let err = parse_template_str(s).unwrap_err();
        match err {
            TemplateLoadError::Validation(msg) => assert!(msg.contains("requires choices")),
            _ => panic!("expected validation error"),
        }
    }

    #[test]
    fn rejects_json_without_schema() {
        let s = r#"
        {
          docs: [
            {
              doc_identity: { id: "d1", label: "Doc 1", ver: "v1.0" },
              doc_hash: { algo: "sha256", hash: "00" },
              sections: [
                {
                  section_id: "s1",
                  text: "Hello.",
                  inputs_spec: [
                    { key: "meta", label: "Meta", type: "json", required: true }
                  ]
                }
              ]
            }
          ]
        }
        "#;

        let err = parse_template_str(s).unwrap_err();
        match err {
            TemplateLoadError::Validation(msg) => {
                assert!(msg.contains("type=json requires schema"))
            }
            _ => panic!("expected validation error"),
        }
    }
}
