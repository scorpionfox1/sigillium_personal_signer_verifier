# Document Wizard Template Specification (v1)

Status: **Draft / pre-1.0**  
Format: **JSON5**, UTF-8

This document specifies the **template file format** consumed by the Sigillium Document Wizard and the rules used to verify and process templates.

---

## 1. Top-level structure

A template file is a JSON5 object:

```json5
{
  template_id: "optional-string",
  template_desc: "optional-string",
  docs: [ /* 1+ documents */ ]
}
```

### Fields
- `template_id` (optional, string)
- `template_desc` (optional, string)
- `docs` (**required**, array, must contain at least 1 document)

Template load fails if `docs` is empty.

---

## 2. Document object

Each entry of `docs[]`:

```json5
{
  doc_identity: { id: "…", label: "…", ver: "…" },
  doc_hash: { algo: "sha256", hash: "…hex…" },
  sections: [ /* 1+ sections */ ]
}
```

### 2.1 doc_identity (required)
```json5
doc_identity: {
  id: "non-empty",
  label: "non-empty",
  ver: "non-empty"
}
```

- `id` (string, required, non-empty)
- `label` (string, required, non-empty)
- `ver` (string, required, non-empty)

### 2.2 doc_hash (required)
```json5
doc_hash: {
  algo: "sha256",
  hash: "64-hex-chars"
}
```

- `algo` (required): currently only `"sha256"` is supported.
- `hash` (required): hex string. Case-insensitive compare is used for expected vs computed.

---

## 3. Section object

Each entry of `sections[]`:

```json5
{
  section_id: "non-empty",
  title: "optional string",
  text: "non-empty string",
  translation: { lang: "…", text: "…" }, // optional
  inputs_spec: [ /* optional */ ]
}
```

### Fields
- `section_id` (required, string, non-empty)
- `title` (optional, string)
- `text` (required, string, non-empty)
- `translation` (optional object):
  - `lang` (string)
  - `text` (string)
- `inputs_spec` (optional array of InputSpec)

---

## 4. Input tags in section text

Section text may reference inputs using tags of the form:

- `[[key]]`

A tag is recognized only if `key` matches `[A-Za-z0-9_]+`.

All tags must have a matching declared input key.

---

## 5. Canonical document text & hashing

Section texts are normalized (CRLF/CR → LF), joined with `\n`, and hashed using SHA‑256 over UTF‑8 bytes.

---

## 6. inputs_spec and input declaration rules

All inputs for a document are the union of all section `inputs_spec` arrays.

Duplicate keys across sections are a hard error.

---

## 7. InputSpec object

```json5
{
  key: "non-empty",
  label: "non-empty",
  type: "string|enum|number|int|date|bool|json",
  required: true|false,
  validators: [ "uuid", "hex", "regex:…", "min_len:N", "max_len:N", "min:X", "max:X" ], // optional
  choices: [ "A", "B" ],     // required for enum
  schema: { /* JSON Schema */ }, // required for json
  sample_json: { /* any JSON value */ } // optional
}
```

---

## 8. Bundle output

The wizard produces:

```json
{
  "signed_utc": "{{~signed_utc}}",
  "canonical_id": "{{~assoc_key_id}}",
  "docs": [
    {
      "doc_identity": { "id": "...", "label": "...", "ver": "..." },
      "doc_hash": { "hash": "...", "algo": "sha256" },
      "doc_inputs": { /* key -> JSON value */ }
    }
  ]
}
```

---

## 9. Minimal example

```json5
{
  template_id: "example-v1",
  docs: [
    {
      doc_identity: { id: "doc1", label: "Example Document", ver: "v1.0" },
      doc_hash: { algo: "sha256", hash: "PUT_EXPECTED_HASH_HERE" },
      sections: [
        {
          section_id: "intro",
          text: "Hello [[name]].",
          inputs_spec: [
            { key: "name", label: "Name", type: "string", required: true }
          ]
        }
      ]
    }
  ]
}
```