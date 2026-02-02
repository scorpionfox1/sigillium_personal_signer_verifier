// src/command/document_wizard/types.rs

use crate::template::doc_wizard::{BundleTemplate, HashAlgo, SectionTemplate};
use serde_json::Value as JsonValue;
use std::collections::{BTreeMap, BTreeSet};

/// Wizard output: a JSON message to be signed (tags intentionally preserved).
///
/// {
///   "signed_utc": "{{~signed_utc}}",
///   "canonical_id": "{{~assoc_key_id}}",
///   "docs": [
///      {
///        "doc_identity": { "id":  "label":  "ver": "v1.0" },
///        "doc_hash": { "hash":  "algo": "sha256" },
///        "doc_inputs": {  }
///      },
///
///   ]
/// }

#[derive(Debug, Clone)]
pub struct WizardState {
    pub template: BundleTemplate,
    pub docs: Vec<DocRunState>,
    pub doc_index: usize,
}

#[derive(Debug, Clone)]
pub struct DocRunState {
    pub doc_identity: crate::template::doc_wizard::DocIdentity,

    /// Optional UI-only intro shown in the wizard. Not part of signed material.
    pub doc_about: Option<String>,

    pub sections: Vec<SectionTemplate>,
    pub expected_hash_hex: String,
    pub computed_hash_hex: String,
    pub hash_algo: HashAlgo,

    /// Tags referenced in canonical doc text (union of all section authoritative text).
    pub referenced_tags: BTreeSet<String>,

    /// Inputs declared in the template (union of all section inputs_spec keys).
    pub declared_inputs: BTreeSet<String>,

    /// Hard template problems that prevent advancing.
    pub template_errors: Vec<String>,

    /// Soft template warnings (helpful for authors).
    pub template_warnings: Vec<String>,

    /// Current user-provided inputs (flat doc_inputs map).
    pub doc_inputs: BTreeMap<String, JsonValue>,
}

#[derive(Debug)]
pub enum WizardError {
    Io(std::io::Error),
    TemplateParse(crate::template::doc_wizard::TemplateLoadError),
    TemplateProblem(String),
    InvalidState(String),
    InputProblem(String),
    InvalidSectionIndex {
        section_index: usize,
        section_count: usize,
    },
}

impl std::fmt::Display for WizardError {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            WizardError::Io(e) => write!(f, "I/O error: {e}"),
            WizardError::TemplateParse(e) => write!(f, "{e}"),
            WizardError::TemplateProblem(msg) => write!(f, "{msg}"),
            WizardError::InvalidState(msg) => write!(f, "{msg}"),
            WizardError::InputProblem(msg) => write!(f, "{msg}"),
            WizardError::InvalidSectionIndex {
                section_index,
                section_count,
            } => {
                write!(
                    f,
                    "invalid section index {section_index}; section_count={section_count}"
                )
            }
        }
    }
}

impl std::error::Error for WizardError {}

impl From<std::io::Error> for WizardError {
    fn from(e: std::io::Error) -> Self {
        WizardError::Io(e)
    }
}

impl From<crate::template::doc_wizard::TemplateLoadError> for WizardError {
    fn from(e: crate::template::doc_wizard::TemplateLoadError) -> Self {
        WizardError::TemplateParse(e)
    }
}
