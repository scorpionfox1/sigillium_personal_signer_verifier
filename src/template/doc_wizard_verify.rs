// src/template/doc_wizard_verify.rs

use std::collections::BTreeSet;

/// Normalize text for hashing/verification:
/// - Treat input as Unicode text
/// - Normalize line endings: CRLF and CR -> LF
/// - Do NOT trim whitespace
/// - Do NOT perform Unicode normalization (NFC/NFD)
pub fn normalize_text_crlf_to_lf(s: &str) -> String {
    // Fast path: if there's no '\r', return as-is.
    if !s.as_bytes().contains(&b'\r') {
        return s.to_string();
    }

    // Replace CRLF and CR with LF.
    // Implementation: iterate chars; when seeing '\r', skip it and (if next is '\n') let '\n' be emitted.
    // But since we're iterating chars, easiest is a byte-based pass.
    let bytes = s.as_bytes();
    let mut out = Vec::with_capacity(bytes.len());

    let mut i = 0;
    while i < bytes.len() {
        match bytes[i] {
            b'\r' => {
                // If next is '\n', skip '\r' and let '\n' be handled by next iteration (or emit '\n' here and skip next).
                // We'll emit '\n' once and skip optional following '\n'.
                out.push(b'\n');
                if i + 1 < bytes.len() && bytes[i + 1] == b'\n' {
                    i += 2;
                } else {
                    i += 1;
                }
            }
            b => {
                out.push(b);
                i += 1;
            }
        }
    }

    // Safety: input was &str (UTF-8). We only substituted '\r' sequences with '\n' bytes.
    // This preserves valid UTF-8.
    String::from_utf8(out).expect("normalize_text_crlf_to_lf: internal UTF-8 invariant violated")
}

/// Join authoritative section texts into the canonical document text for hashing:
/// - Normalize each section's line endings (CRLF/CR -> LF)
/// - Join sections with a single '\n' between them
pub fn canonical_doc_text_from_sections<'a>(sections: impl IntoIterator<Item = &'a str>) -> String {
    let mut it = sections.into_iter();

    let Some(first) = it.next() else {
        // Caller should already enforce "1+ sections", but keep this safe.
        return String::new();
    };

    let mut out = normalize_text_crlf_to_lf(first);
    for s in it {
        out.push('\n');
        out.push_str(&normalize_text_crlf_to_lf(s));
    }
    out
}

/// Compute SHA-256 of the canonical document text (UTF-8) and return lowercase hex.
pub fn sha256_hex_of_text(text: &str) -> String {
    use sha2::{Digest, Sha256};

    let mut h = Sha256::new();
    h.update(text.as_bytes());
    let digest = h.finalize();

    // Hex encoding without extra deps.
    let mut out = String::with_capacity(digest.len() * 2);
    for b in digest {
        out.push(nibble_to_hex((b >> 4) & 0x0f));
        out.push(nibble_to_hex(b & 0x0f));
    }
    out
}

fn nibble_to_hex(n: u8) -> char {
    match n {
        0..=9 => (b'0' + n) as char,
        10..=15 => (b'a' + (n - 10)) as char,
        _ => unreachable!("nibble_to_hex: out of range"),
    }
}

/// Extract input tags of the form [[key]] from text.
///
/// Strict rules:
/// - Tag opens with "[[" and closes with "]]"
/// - `key` must match: [A-Za-z0-9_]+
/// - Tags that don't match the strict pattern are ignored (not treated as tags)
pub fn extract_input_tags(text: &str) -> BTreeSet<String> {
    let bytes = text.as_bytes();
    let mut out = BTreeSet::new();

    let mut i = 0;
    while i + 1 < bytes.len() {
        if bytes[i] == b'[' && bytes[i + 1] == b'[' {
            // Find closing "]]"
            let start = i + 2;
            let mut j = start;

            // Scan until we find "]]" or hit end.
            while j + 1 < bytes.len() {
                if bytes[j] == b']' && bytes[j + 1] == b']' {
                    break;
                }
                j += 1;
            }

            // If we didn't find a close, we're done.
            if j + 1 >= bytes.len() {
                break;
            }

            // Candidate key is bytes[start..j]
            if j > start {
                if let Ok(key) = std::str::from_utf8(&bytes[start..j]) {
                    if is_strict_tag_key(key) {
                        out.insert(key.to_string());
                    }
                }
            }

            // Move past the closing brackets.
            i = j + 2;
            continue;
        }

        i += 1;
    }

    out
}

fn is_strict_tag_key(s: &str) -> bool {
    if s.is_empty() {
        return false;
    }
    s.bytes()
        .all(|b| matches!(b, b'a'..=b'z' | b'A'..=b'Z' | b'0'..=b'9' | b'_'))
}

/// Validate that every tag referenced in the document text has a corresponding declared input key.
/// Returns Ok(()) if coverage is complete; otherwise returns Err with a human-readable message.
pub fn validate_tag_coverage(
    referenced_tags: &BTreeSet<String>,
    declared_inputs: &BTreeSet<String>,
) -> Result<(), String> {
    let mut missing: Vec<String> = Vec::new();
    for t in referenced_tags.iter() {
        if !declared_inputs.contains(t) {
            missing.push(t.clone());
        }
    }

    if missing.is_empty() {
        Ok(())
    } else {
        Err(format!(
            "missing input specs for tags: {}",
            missing.join(", ")
        ))
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn normalize_crlf_to_lf() {
        let s = "a\r\nb\r\nc";
        assert_eq!(normalize_text_crlf_to_lf(s), "a\nb\nc");
    }

    #[test]
    fn normalize_cr_to_lf() {
        let s = "a\rb\rc";
        assert_eq!(normalize_text_crlf_to_lf(s), "a\nb\nc");
    }

    #[test]
    fn canonical_join_sections_with_single_newline() {
        let s = canonical_doc_text_from_sections(["one", "two", "three"]);
        assert_eq!(s, "one\ntwo\nthree");
    }

    #[test]
    fn canonical_join_normalizes_each_section() {
        let s = canonical_doc_text_from_sections(["one\r\ntwo", "three\rfour"]);
        assert_eq!(s, "one\ntwo\nthree\nfour");
    }

    #[test]
    fn extract_tags_basic() {
        let t = "Hello [[person_id]] and [[email]].";
        let tags = extract_input_tags(t);
        assert!(tags.contains("person_id"));
        assert!(tags.contains("email"));
        assert_eq!(tags.len(), 2);
    }

    #[test]
    fn extract_tags_ignores_invalid_keys() {
        let t = "Bad [[with space]] and bad [[dash-key]] and ok [[good_key_1]].";
        let tags = extract_input_tags(t);
        assert!(tags.contains("good_key_1"));
        assert!(!tags.contains("with space"));
        assert!(!tags.contains("dash-key"));
        assert_eq!(tags.len(), 1);
    }

    #[test]
    fn validate_tag_coverage_ok() {
        let tags = BTreeSet::from(["a".to_string(), "b".to_string()]);
        let inputs = BTreeSet::from(["a".to_string(), "b".to_string(), "c".to_string()]);
        assert!(validate_tag_coverage(&tags, &inputs).is_ok());
    }

    #[test]
    fn validate_tag_coverage_missing() {
        let tags = BTreeSet::from(["a".to_string(), "b".to_string()]);
        let inputs = BTreeSet::from(["a".to_string()]);
        let err = validate_tag_coverage(&tags, &inputs).unwrap_err();
        assert!(err.contains("b"));
    }

    #[test]
    fn sha256_hex_is_lowercase_hex_length_64() {
        let h = sha256_hex_of_text("abc");
        assert_eq!(h.len(), 64);
        assert!(h.bytes().all(|b| matches!(b, b'0'..=b'9' | b'a'..=b'f')));
    }

    #[test]
    fn normalize_crlf_and_cr_to_lf() {
        let s = "a\r\nb\rc\n";
        assert_eq!(normalize_text_crlf_to_lf(s), "a\nb\nc\n");
    }

    #[test]
    fn extract_tags_finds_all_unique_tags() {
        let text = "Hello [[a]] [[b]] [[a]]";
        let tags = extract_input_tags(text);

        assert_eq!(tags.len(), 2);
        assert!(tags.contains("a"));
        assert!(tags.contains("b"));
    }

    #[test]
    fn extract_tags_ignores_non_strict_tags() {
        // invalid keys should be ignored:
        // - contains dash
        // - contains space
        // - empty
        let text = "x [[a-b]] y [[a b]] z [[]] ok [[a_b09]]";
        let tags = extract_input_tags(text);

        assert_eq!(tags.len(), 1);
        assert!(tags.contains("a_b09"));
    }

    #[test]
    fn sha256_hex_is_stable() {
        let h1 = sha256_hex_of_text("abc");
        let h2 = sha256_hex_of_text("abc");
        assert_eq!(h1, h2);
    }

    #[test]
    fn tag_coverage_detects_missing() {
        let referenced = BTreeSet::from(["a".to_string(), "b".to_string()]);
        let declared = BTreeSet::from(["a".to_string()]);

        let err = validate_tag_coverage(&referenced, &declared).unwrap_err();
        assert!(err.contains("missing input specs for tags:"));
        assert!(err.contains("b"));
    }
}
