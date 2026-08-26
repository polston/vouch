//! Snippet extraction: turning declared `[[tool.snippet]]` field paths, plus
//! one tool call's input map, into (text, language) pairs for the scanners
//! to decide on — every language registered in `syntax`, currently bash,
//! powershell, and python. `route::decide_tool` builds the merged input map and
//! consumes `extract` (it did not when this module was written, and the header
//! said so until 2026-08-07).
//!
//! Fail-closed by construction, matching CLAUDE.md §1 (vouch is an
//! allow-list): any declared snippet that cannot be FULLY resolved — a
//! missing field, the wrong JSON type, an empty string, an empty array, or
//! any element of a `[]`-mapped array missing its sub-field — refuses the
//! WHOLE batch, naming what was missing. A batch is never decided on a
//! subset; a `Refused` message is what the ask prompt shows the operator.

use crate::guards::ToolSnippet;
use serde_json::{Map, Value};

/// The result of extracting every declared snippet from one tool call's
/// input map.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum Extracted {
    /// One (text, language) pair per resolved snippet element, in input
    /// order. `language` is one of `knowledge::snippet_languages()`.
    Ok(Vec<(String, String)>),
    /// Fail-closed: names what was missing, empty, wrong-shaped, or
    /// unmapped. Callers turn this into an ask prompt.
    Refused(String),
}

/// Resolve every declared snippet against `input`, the merged `tool_input`
/// field map (extraction never knows which of its fields were typed vs.
/// `extra` — Task 7 builds that map before calling this).
///
/// The moment any declared snippet cannot be fully resolved, the whole call
/// refuses — never a partial result for the snippets that did resolve.
///
/// `snippets` empty is not this function's case: callers only reach here
/// once a tool is known to declare at least one snippet field.
pub fn extract(snippets: &[ToolSnippet], input: &Map<String, Value>) -> Extracted {
    debug_assert!(
        !snippets.is_empty(),
        "extract called with no snippet declarations — callers must not reach here for a tool \
         with zero declared snippets"
    );

    let mut out = Vec::new();
    for p in snippets {
        let language = match resolve_language(p, input) {
            Ok(l) => l,
            Err(msg) => return Extracted::Refused(msg),
        };
        let texts = match resolve_field(input, &p.field) {
            Ok(t) => t,
            Err(msg) => return Extracted::Refused(msg),
        };
        out.extend(texts.into_iter().map(|text| (text, language.clone())));
    }
    Extracted::Ok(out)
}

/// A fixed `language` is used verbatim. `language_from` reads a sibling
/// field FROM THE SAME MAP LEVEL AS THE SNIPPET DECLARATION'S ROOT — the
/// top-level `input` map, never a level nested alongside `field` — and
/// translates its value through `language_values`.
///
/// Load validation (`knowledge::validate_tool_snippet`) already guarantees
/// exactly one of `language` / `language_from` is set, so the `expect` below
/// documents that contract rather than re-checking it.
fn resolve_language(p: &ToolSnippet, input: &Map<String, Value>) -> Result<String, String> {
    if let Some(lang) = &p.language {
        return Ok(lang.clone());
    }

    let from = p.language_from.as_ref().expect(
        "ToolSnippet load validation guarantees exactly one of language / language_from is set",
    );

    let raw = match input.get(from.as_str()) {
        Some(Value::String(s)) => s,
        Some(other) => {
            return Err(format!(
                "snippet field {:?}: language_from {from:?} is not a string (found {})",
                p.field,
                json_type_name(other)
            ));
        }
        None => {
            return Err(format!(
                "snippet field {:?}: language_from {from:?} is missing from the input",
                p.field
            ));
        }
    };

    let mapped = p
        .language_values
        .as_ref()
        .and_then(|values| values.get(raw.as_str()));
    match mapped {
        Some(lang) => Ok(lang.clone()),
        None => Err(format!(
            "snippet field {:?}: language_from {from:?} = {raw:?} has no entry in language_values",
            p.field
        )),
    }
}

/// Resolve one `field` path against `input`: split on `.`, walk each dotted
/// step, and map over any step ending `[]`. No wildcards, no escaping — a
/// key that literally contains `.` or `[]` is inexpressible by this
/// mini-language and simply will not match, which fails closed on its own.
fn resolve_field(input: &Map<String, Value>, field: &str) -> Result<Vec<String>, String> {
    let steps: Vec<&str> = field.split('.').collect();
    walk_object(input, &steps, field)
}

/// Look up the first `step` in `obj`, then either map over it (an array
/// step, `key[]`) or continue descending (a plain step, `key`).
fn walk_object(
    obj: &Map<String, Value>,
    steps: &[&str],
    full_field: &str,
) -> Result<Vec<String>, String> {
    let (step, rest) = steps.split_first().expect(
        "field path splits into at least one step: str::split on a non-empty separator-free \
         string always yields >= 1 element",
    );
    let is_array_step = step.ends_with("[]");
    let key = if is_array_step { &step[..step.len() - 2] } else { *step };

    let Some(next) = obj.get(key) else {
        return Err(format!("snippet field {full_field:?}: missing {key:?}"));
    };

    if is_array_step {
        walk_array(next, key, rest, full_field)
    } else if rest.is_empty() {
        terminal_string(next, full_field)
    } else {
        let Some(nested) = next.as_object() else {
            return Err(format!(
                "snippet field {full_field:?}: expected an object at {key:?}, found {}",
                json_type_name(next)
            ));
        };
        walk_object(nested, rest, full_field)
    }
}

/// Map the remaining `rest` steps over every element of `value`, which must
/// be a non-empty JSON array. Any single element's failure refuses the
/// whole field — a batch is never decided on a subset.
fn walk_array(
    value: &Value,
    key: &str,
    rest: &[&str],
    full_field: &str,
) -> Result<Vec<String>, String> {
    let Some(arr) = value.as_array() else {
        return Err(format!(
            "snippet field {full_field:?}: {key:?} is not an array (found {})",
            json_type_name(value)
        ));
    };
    if arr.is_empty() {
        return Err(format!(
            "snippet field {full_field:?}: {key:?} is an empty array"
        ));
    }

    let mut out = Vec::new();
    for (i, elem) in arr.iter().enumerate() {
        let resolved = if rest.is_empty() {
            terminal_string(elem, full_field)
        } else {
            match elem.as_object() {
                Some(nested) => walk_object(nested, rest, full_field),
                None => Err(format!(
                    "snippet field {full_field:?}: element {i} of {key:?} is not an object \
                     (found {})",
                    json_type_name(elem)
                )),
            }
        };
        match resolved {
            Ok(mut v) => out.append(&mut v),
            Err(msg) => {
                return Err(format!("{msg} (element {i} of {key:?})"));
            }
        }
    }
    Ok(out)
}

/// The end of a field path must be a JSON string with real content — the
/// snippet text itself. A whitespace-only string is a no-op the same way an
/// empty one is: let through, it parses to zero complete commands downstream
/// and falls straight to an unscrutinised allow, so it fails closed here
/// too, in the same place the empty-string check lives.
fn terminal_string(value: &Value, full_field: &str) -> Result<Vec<String>, String> {
    match value {
        Value::String(s) if !s.trim().is_empty() => Ok(vec![s.clone()]),
        Value::String(_) => Err(format!(
            "snippet field {full_field:?} is empty or whitespace-only"
        )),
        other => Err(format!(
            "snippet field {full_field:?} is not a string (found {})",
            json_type_name(other)
        )),
    }
}

fn json_type_name(v: &Value) -> &'static str {
    match v {
        Value::Null => "null",
        Value::Bool(_) => "bool",
        Value::Number(_) => "number",
        Value::String(_) => "string",
        Value::Array(_) => "array",
        Value::Object(_) => "object",
    }
}
