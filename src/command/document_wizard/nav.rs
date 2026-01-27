// src/command/document_wizard/nav.rs

use crate::{
    command::document_wizard::{
        types::{WizardError, WizardState},
        validate_current_doc_inputs, DocRunState,
    },
    template::doc_wizard::SectionTemplate,
};

pub fn current_doc(state: &WizardState) -> Result<&DocRunState, WizardError> {
    state
        .docs
        .get(state.doc_index)
        .ok_or_else(|| WizardError::InvalidState("doc_index out of range".to_string()))
}

pub fn current_doc_mut(state: &mut WizardState) -> Result<&mut DocRunState, WizardError> {
    state
        .docs
        .get_mut(state.doc_index)
        .ok_or_else(|| WizardError::InvalidState("doc_index out of range".to_string()))
}

pub fn can_advance_doc(state: &WizardState) -> Result<bool, WizardError> {
    let d = current_doc(state)?;
    Ok(d.template_errors.is_empty())
}

pub fn advance_doc(state: &mut WizardState) -> Result<(), WizardError> {
    let can = can_advance_doc(state)?;
    if !can {
        let d = current_doc(state)?;
        return Err(WizardError::TemplateProblem(format!(
            "cannot advance: doc '{}' has template errors: {}",
            d.doc_identity.label,
            d.template_errors.join(" | ")
        )));
    }

    // Also enforce input validity for current doc before advancing.
    validate_current_doc_inputs(state)?;

    if state.doc_index + 1 >= state.docs.len() {
        return Err(WizardError::InvalidState(
            "already at last document".to_string(),
        ));
    }
    state.doc_index += 1;
    Ok(())
}

pub fn rewind_doc(state: &mut WizardState) -> Result<(), WizardError> {
    if state.doc_index == 0 {
        return Err(WizardError::InvalidState(
            "cannot rewind before first document".to_string(),
        ));
    }

    state.doc_index -= 1;
    Ok(())
}

pub fn back_doc(state: &mut WizardState) -> Result<(), WizardError> {
    if state.doc_index == 0 {
        return Err(WizardError::InvalidState(
            "already at first document".to_string(),
        ));
    }
    state.doc_index -= 1;
    Ok(())
}

pub fn doc_count(wiz: &WizardState) -> usize {
    wiz.docs.len()
}

pub fn section_count_current_doc(wiz: &WizardState) -> Result<usize, WizardError> {
    let d = current_doc(wiz)?;
    Ok(d.sections.len())
}

pub fn current_section(
    wiz: &WizardState,
    section_index: usize,
) -> Result<&SectionTemplate, WizardError> {
    let d = current_doc(wiz)?;
    d.sections
        .get(section_index)
        .ok_or_else(|| WizardError::InvalidSectionIndex {
            section_index,
            section_count: d.sections.len(),
        })
}

// ======================================================
// Unit Tests
// ======================================================

#[cfg(test)]
mod tests {
    use super::*;
    use crate::command::document_wizard::types::{DocRunState, WizardError, WizardState};
    use crate::template::doc_wizard::{BundleTemplate, DocIdentity, HashAlgo, SectionTemplate};
    use serde_json::Value as JsonValue;
    use std::collections::{BTreeMap, BTreeSet};

    fn mk_section(section_id: &str) -> SectionTemplate {
        SectionTemplate {
            section_id: section_id.to_string(),
            title: None,
            text: "Hello.".to_string(),
            translation: None,
            inputs_spec: None,
        }
    }

    fn mk_doc(label: &str, template_errors: Vec<String>) -> DocRunState {
        DocRunState {
            doc_identity: DocIdentity {
                id: "d1".to_string(),
                label: label.to_string(),
                ver: "v1.0".to_string(),
            },
            sections: vec![mk_section("s1")],
            expected_hash_hex: "00".to_string(),
            computed_hash_hex: "00".to_string(),
            hash_algo: HashAlgo::Sha256,
            referenced_tags: BTreeSet::new(),
            declared_inputs: BTreeSet::new(),
            template_errors,
            template_warnings: vec![],
            doc_inputs: BTreeMap::<String, JsonValue>::new(),
        }
    }

    fn mk_state(docs: Vec<DocRunState>, doc_index: usize) -> WizardState {
        WizardState {
            template: BundleTemplate {
                template_id: None,
                template_desc: None,
                docs: vec![],
            },
            docs,
            doc_index,
        }
    }

    #[test]
    fn current_doc_out_of_range_is_invalid_state() {
        let state = mk_state(vec![mk_doc("Doc 1", vec![])], 5);
        let err = current_doc(&state).unwrap_err();
        assert!(matches!(err, WizardError::InvalidState(_)));
    }

    #[test]
    fn current_section_invalid_index_returns_invalid_section_index() {
        let state = mk_state(vec![mk_doc("Doc 1", vec![])], 0);
        let err = current_section(&state, 99).unwrap_err();
        assert!(matches!(
            err,
            WizardError::InvalidSectionIndex {
                section_index: 99,
                ..
            }
        ));
    }

    #[test]
    fn can_advance_doc_false_when_template_errors_present() {
        let state = mk_state(vec![mk_doc("Doc 1", vec!["bad".to_string()])], 0);
        let can = can_advance_doc(&state).unwrap();
        assert!(!can);
    }

    #[test]
    fn advance_doc_fails_with_template_problem_when_template_errors_present() {
        let mut state = mk_state(vec![mk_doc("Doc 1", vec!["bad".to_string()])], 0);
        let err = advance_doc(&mut state).unwrap_err();
        assert!(matches!(err, WizardError::TemplateProblem(_)));
    }

    #[test]
    fn advance_doc_fails_at_last_document() {
        let mut state = mk_state(vec![mk_doc("Doc 1", vec![])], 0);
        let err = advance_doc(&mut state).unwrap_err();
        assert!(matches!(err, WizardError::InvalidState(_)));
    }

    #[test]
    fn advance_doc_increments_index_on_success() {
        let mut state = mk_state(vec![mk_doc("Doc 1", vec![]), mk_doc("Doc 2", vec![])], 0);
        advance_doc(&mut state).unwrap();
        assert_eq!(state.doc_index, 1);
    }

    #[test]
    fn rewind_doc_blocks_before_first() {
        let mut state = mk_state(vec![mk_doc("Doc 1", vec![])], 0);
        let err = rewind_doc(&mut state).unwrap_err();
        assert!(matches!(err, WizardError::InvalidState(_)));
    }

    #[test]
    fn back_doc_blocks_before_first() {
        let mut state = mk_state(vec![mk_doc("Doc 1", vec![])], 0);
        let err = back_doc(&mut state).unwrap_err();
        assert!(matches!(err, WizardError::InvalidState(_)));
    }
}
