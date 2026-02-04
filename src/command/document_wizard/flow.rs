// src/command/document_wizard/flow.rs

//! Wizard flow (doc/section/phase stepping) helpers.
//!
//! These helpers are intentionally UI-agnostic. The egui panel owns the UI state
//! (e.g., which section is selected), but the transitions between wizard steps
//! belong here.

use crate::command::document_wizard::nav;
use crate::command::document_wizard::types::{WizardError, WizardState, WizardStepPhase};
use crate::template::doc_wizard::SectionTemplate;

pub fn all_docs_have_no_template_errors(wiz: &WizardState) -> bool {
    wiz.docs.iter().all(|d| d.template_errors.is_empty())
}

pub fn section_has_translation(s: &SectionTemplate) -> bool {
    s.translation
        .as_ref()
        .map(|t| !t.text.trim().is_empty())
        .unwrap_or(false)
}

pub fn section_has_inputs(s: &SectionTemplate) -> bool {
    s.inputs_spec
        .as_ref()
        .map(|v| !v.is_empty())
        .unwrap_or(false)
}

pub fn doc_has_about(wiz: &WizardState) -> bool {
    wiz.docs
        .get(wiz.doc_index)
        .and_then(|d| d.doc_about.as_ref())
        .map(|s| !s.trim().is_empty())
        .unwrap_or(false)
}

pub fn current_doc_about(wiz: &WizardState) -> Option<&str> {
    wiz.docs
        .get(wiz.doc_index)
        .and_then(|d| d.doc_about.as_deref())
        .map(|s| s.trim())
        .filter(|s| !s.is_empty())
}

pub fn step_next(
    wiz: &mut WizardState,
    section_index: &mut usize,
    phase: &mut WizardStepPhase,
) -> Result<(), WizardError> {
    // About step: just move into the normal section flow (or skip doc if no sections).
    if matches!(*phase, WizardStepPhase::About) {
        let has_sections = wiz
            .docs
            .get(wiz.doc_index)
            .map(|d| !d.sections.is_empty())
            .unwrap_or(false);

        if has_sections {
            *phase = WizardStepPhase::Text;
        } else {
            // edge case: doc has about but no sections
            advance_to_next_section_or_doc(wiz, section_index, phase)?;
        }
        return Ok(());
    }

    // From here on, we can safely immutably borrow doc/section.
    let Some(doc) = wiz.docs.get(wiz.doc_index) else {
        return Ok(());
    };

    let Some(sec) = doc.sections.get(*section_index) else {
        return Ok(());
    };

    match *phase {
        WizardStepPhase::Text => {
            if section_has_translation(sec) {
                *phase = WizardStepPhase::Translation;
            } else if section_has_inputs(sec) {
                *phase = WizardStepPhase::Inputs;
            } else {
                // no translation + no inputs: advance section/doc
                advance_to_next_section_or_doc(wiz, section_index, phase)?;
            }
        }
        WizardStepPhase::Translation => {
            if section_has_inputs(sec) {
                *phase = WizardStepPhase::Inputs;
            } else {
                advance_to_next_section_or_doc(wiz, section_index, phase)?;
            }
        }
        WizardStepPhase::Inputs => {
            advance_to_next_section_or_doc(wiz, section_index, phase)?;
        }

        // Should be unreachable because About returns above, but keeps match exhaustive and future-proof.
        WizardStepPhase::About => {}
    }

    Ok(())
}

pub fn advance_to_next_section_or_doc(
    wiz: &mut WizardState,
    section_index: &mut usize,
    phase: &mut WizardStepPhase,
) -> Result<(), WizardError> {
    let doc_section_count = wiz
        .docs
        .get(wiz.doc_index)
        .map(|d| d.sections.len())
        .unwrap_or(0);

    if doc_section_count > 0 && *section_index + 1 < doc_section_count {
        *section_index += 1;
        *phase = WizardStepPhase::Text;
        return Ok(());
    }

    // next doc
    if wiz.doc_index + 1 < wiz.docs.len() {
        nav::advance_doc(wiz)?;
        *section_index = 0;
        *phase = if doc_has_about(wiz) {
            WizardStepPhase::About
        } else {
            WizardStepPhase::Text
        };
    }

    Ok(())
}

pub fn step_back(
    wiz: &mut WizardState,
    section_index: &mut usize,
    phase: &mut WizardStepPhase,
) -> Result<(), WizardError> {
    // About step: back to previous doc end (or no-op if already at first doc).
    if matches!(*phase, WizardStepPhase::About) {
        back_to_prev_section_or_doc(wiz, section_index, phase)?;
        return Ok(());
    }

    // If we're at the first section text and this doc has About, go back to About.
    if matches!(*phase, WizardStepPhase::Text) && *section_index == 0 && doc_has_about(wiz) {
        *phase = WizardStepPhase::About;
        return Ok(());
    }

    // From here on, only Translation/Inputs need to look at the current section.
    let Some(doc) = wiz.docs.get(wiz.doc_index) else {
        return Ok(());
    };
    let Some(sec) = doc.sections.get(*section_index) else {
        return Ok(());
    };

    match *phase {
        WizardStepPhase::Inputs => {
            if section_has_translation(sec) {
                *phase = WizardStepPhase::Translation;
            } else {
                *phase = WizardStepPhase::Text;
            }
        }
        WizardStepPhase::Translation => {
            *phase = WizardStepPhase::Text;
        }
        WizardStepPhase::Text => {
            back_to_prev_section_or_doc(wiz, section_index, phase)?;
        }

        // Unreachable due to early return above, but keeps the match exhaustive.
        WizardStepPhase::About => {}
    }

    Ok(())
}

pub fn back_to_prev_section_or_doc(
    wiz: &mut WizardState,
    section_index: &mut usize,
    phase: &mut WizardStepPhase,
) -> Result<(), WizardError> {
    if *section_index > 0 {
        *section_index -= 1;
        set_phase_to_last_step_in_section(wiz, *section_index, phase);
        return Ok(());
    }

    if wiz.doc_index > 0 {
        nav::back_doc(wiz)?;
        let sc = wiz
            .docs
            .get(wiz.doc_index)
            .map(|d| d.sections.len())
            .unwrap_or(0);
        *section_index = sc.saturating_sub(1);
        set_phase_to_last_step_in_section(wiz, *section_index, phase);
    }

    Ok(())
}

pub fn set_phase_to_last_step_in_section(
    wiz: &WizardState,
    section_index: usize,
    phase: &mut WizardStepPhase,
) {
    let Some(sec) = current_section_opt(wiz, section_index) else {
        *phase = WizardStepPhase::Text;
        return;
    };

    if section_has_inputs(sec) {
        *phase = WizardStepPhase::Inputs;
    } else if section_has_translation(sec) {
        *phase = WizardStepPhase::Translation;
    } else {
        *phase = WizardStepPhase::Text;
    }
}

pub fn is_last_step(wiz: &WizardState, section_index: usize, phase: WizardStepPhase) -> bool {
    let doc_count = wiz.docs.len();
    let doc_index = wiz.doc_index;
    let Some(doc) = wiz.docs.get(doc_index) else {
        return true;
    };

    // About is never the last step if there are any sections.
    if matches!(phase, WizardStepPhase::About) {
        return doc.sections.is_empty() && (doc_index + 1 >= doc_count);
    }

    let section_count = doc.sections.len();
    let Some(sec) = doc.sections.get(section_index) else {
        return true;
    };

    // Determine whether there is any step after the current one.
    match phase {
        WizardStepPhase::Text => {
            if section_has_translation(sec) {
                return false;
            }
            if section_has_inputs(sec) {
                return false;
            }
        }
        WizardStepPhase::Translation => {
            if section_has_inputs(sec) {
                return false;
            }
        }
        WizardStepPhase::Inputs => {}
        WizardStepPhase::About => return doc.sections.is_empty() && (doc_index + 1 >= doc_count),
    }

    if section_index + 1 < section_count {
        return false;
    }

    doc_index + 1 >= doc_count
}

fn current_section_opt<'a>(
    wiz: &'a WizardState,
    section_index: usize,
) -> Option<&'a SectionTemplate> {
    nav::current_section(wiz, section_index).ok()
}
