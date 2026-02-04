// tests/document_wizard_basic.rs

use serde_json::Value as JsonValue;
use sigillium_personal_signer_verifier_lib::command::document_wizard::{
    advance_doc, build_doc_bundle, load_wizard_from_str, set_input_json_from_str_current_doc,
    set_input_value_current_doc,
};
use sigillium_personal_signer_verifier_lib::template::doc_wizard_verify::{
    canonical_doc_text_from_sections, sha256_hex_of_text,
};
use sigillium_personal_signer_verifier_lib::types::{TAG_ASSOC_KEY_ID, TAG_SIGNED_UTC};

fn sample_template_json5() -> String {
    // Doc 1
    let d1_text = "I acknowledge the terms set forth herein.";

    // Doc 2 (two sections joined with "\n")
    let d2_s1 = "Credo in unum Deum.";
    let d2_s2 = "Et in unum Dominum Iesum Christum.";

    // Doc 3
    let d3_text = r#"
This agreement records the declarant's provided information.

Person ID: [[person_id]]
Email: [[email]]
Role: [[role]]
Birth date: [[birth_date]]
Score: [[score]]
Attempts: [[attempts]]
Metadata: [[metadata]]
"#
    .trim();
    let d3_text_json = serde_json::to_string(d3_text).expect("json escape d3_text");

    let d1_hash = sha256_hex_of_text(&canonical_doc_text_from_sections([d1_text]));
    let d2_hash = sha256_hex_of_text(&canonical_doc_text_from_sections([d2_s1, d2_s2]));
    let d3_hash = sha256_hex_of_text(&canonical_doc_text_from_sections([d3_text]));

    format!(
        r#"
{{
  template_id: "sample_bundle_v1",
  docs: [

    {{
      doc_identity: {{ id: "acknowledgement", label: "Acknowledgement", ver: "v1.0" }},
      doc_hash: {{ algo: "sha256", hash: "{d1_hash}" }},
      sections: [
        {{
          section_id: "main",
          text: "{d1_text}"
        }}
      ]
    }},

    {{
      doc_identity: {{ id: "latin_attestation", label: "Latin Attestation", ver: "v1.0" }},
      doc_hash: {{ algo: "sha256", hash: "{d2_hash}" }},
      sections: [
        {{
          section_id: "section_1",
          title: "Prima Pars",
          text: "{d2_s1}",
          translation: {{ lang: "en", text: "I believe in one God." }}
        }},
        {{
          section_id: "section_2",
          title: "Secunda Pars",
          text: "{d2_s2}",
          translation: {{ lang: "en", text: "And in one Lord Jesus Christ." }}
        }}
      ]
    }},

    {{
      doc_identity: {{ id: "declarant_information", label: "Declarant Information", ver: "v1.0" }},
      doc_hash: {{ algo: "sha256", hash: "{d3_hash}" }},
      sections: [
        {{
          section_id: "info",
          text: {d3_text_json},
          inputs_spec: [
            {{
              key: "person_id",
              label: "Person UUID",
              type: "string",
              required: true,
              validators: ["uuid"]
            }},
            {{
              key: "email",
              label: "Email Address",
              type: "string",
              required: true,
              validators: ["regex:^.+@.+\\..+$"]
            }},
            {{
              key: "role",
              label: "Role",
              type: "enum",
              required: true,
              choices: ["member", "admin", "observer"]
            }},
            {{
              key: "birth_date",
              label: "Date of Birth",
              type: "date",
              required: true
            }},
            {{
              key: "score",
              label: "Numeric Score",
              type: "number",
              required: true
            }},
            {{
              key: "attempts",
              label: "Attempt Count",
              type: "int",
              required: true
            }},
            {{
              key: "metadata",
              label: "Metadata JSON",
              type: "json",
              required: true,
              schema: {{
                type: "object",
                required: ["source", "confirmed"],
                properties: {{
                  source: {{ type: "string" }},
                  confirmed: {{ type: "boolean" }}
                }},
                additionalProperties: false
              }}
            }}
          ]
        }}
      ]
    }}

  ]
}}
"#
    )
}

#[test]
fn document_wizard_basic_flow_builds_bundle() {
    let tpl = sample_template_json5();

    let mut w = load_wizard_from_str(&tpl).expect("load wizard");

    // Doc 1: no inputs. Should be able to advance.
    advance_doc(&mut w).expect("advance to doc 2");

    // Doc 2: no inputs. Should be able to advance.
    advance_doc(&mut w).expect("advance to doc 3");

    // Doc 3: set all required inputs.
    set_input_value_current_doc(
        &mut w,
        "person_id",
        JsonValue::String("123e4567-e89b-12d3-a456-426614174000".to_string()),
    )
    .expect("set person_id");
    set_input_value_current_doc(
        &mut w,
        "email",
        JsonValue::String("test@example.com".to_string()),
    )
    .expect("set email");
    set_input_value_current_doc(&mut w, "role", JsonValue::String("member".to_string()))
        .expect("set role");
    set_input_value_current_doc(
        &mut w,
        "birth_date",
        JsonValue::String("2000-01-02".to_string()),
    )
    .expect("set birth_date");
    set_input_value_current_doc(
        &mut w,
        "score",
        JsonValue::Number(serde_json::Number::from_f64(98.5).unwrap()),
    )
    .expect("set score");
    set_input_value_current_doc(
        &mut w,
        "attempts",
        JsonValue::Number(serde_json::Number::from(3)),
    )
    .expect("set attempts");

    // JSON input validated by schema
    set_input_json_from_str_current_doc(
        &mut w,
        "metadata",
        r#"{ "source": "wizard_test", "confirmed": true }"#,
    )
    .expect("set metadata json");

    // Build bundle JSON
    let bundle = build_doc_bundle(&w).expect("build bundle");

    // Basic shape assertions
    assert_eq!(bundle["signed_utc"].as_str().unwrap(), TAG_SIGNED_UTC);
    assert_eq!(bundle["canonical_id"].as_str().unwrap(), TAG_ASSOC_KEY_ID);

    let docs = bundle["docs"].as_array().expect("docs array");
    assert_eq!(docs.len(), 3);

    // Doc identities are present
    assert_eq!(
        docs[0]["doc_identity"]["id"].as_str().unwrap(),
        "acknowledgement"
    );
    assert_eq!(
        docs[1]["doc_identity"]["id"].as_str().unwrap(),
        "latin_attestation"
    );
    assert_eq!(
        docs[2]["doc_identity"]["id"].as_str().unwrap(),
        "declarant_information"
    );

    // Doc 3 inputs present
    let inputs3 = docs[2]["doc_inputs"].as_object().expect("doc_inputs obj");
    assert_eq!(inputs3["role"].as_str().unwrap(), "member");
    assert_eq!(inputs3["attempts"].as_i64().unwrap(), 3);
    assert_eq!(inputs3["metadata"]["confirmed"].as_bool().unwrap(), true);
}
