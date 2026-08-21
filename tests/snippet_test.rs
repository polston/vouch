//! Snippet extraction tests.
//!
//! `extract` turns declared `[[tool.snippet]]` field paths plus a tool call's
//! merged input map into (text, language) pairs. It is fail-closed by
//! construction: any declared snippet that cannot be fully resolved refuses
//! the WHOLE batch, naming what was missing — a subset is never a decision.

use serde_json::json;
use vouch::guards::ToolSnippet;
use vouch::snippet::{extract, Extracted};

fn snippet_lang(field: &str, language: &str) -> ToolSnippet {
    ToolSnippet {
        field: field.to_string(),
        language: Some(language.to_string()),
        language_from: None,
        language_values: None,
    }
}

fn snippet_from(field: &str, language_from: &str, values: &[(&str, &str)]) -> ToolSnippet {
    ToolSnippet {
        field: field.to_string(),
        language: None,
        language_from: Some(language_from.to_string()),
        language_values: Some(
            values
                .iter()
                .map(|(k, v)| (k.to_string(), v.to_string()))
                .collect(),
        ),
    }
}

fn pair(text: &str, language: &str) -> (String, String) {
    (text.to_string(), language.to_string())
}

fn assert_refused_naming(got: Extracted, needle: &str) {
    match got {
        Extracted::Refused(msg) => {
            assert!(
                msg.contains(needle),
                "expected Refused message to name {needle:?}, got {msg:?}"
            );
        }
        other => panic!("expected Refused, got {other:?}"),
    }
}

// ---------------------------------------------------------------------------
// Shapes that resolve
// ---------------------------------------------------------------------------

#[test]
fn dotted_field_descends() {
    let snippets = vec![snippet_lang("script.body", "python")];
    let input = json!({"script": {"body": "print(1)"}})
        .as_object()
        .unwrap()
        .clone();

    let got = extract(&snippets, &input);

    assert_eq!(got, Extracted::Ok(vec![pair("print(1)", "python")]));
}

#[test]
fn array_step_maps_in_order() {
    let snippets = vec![snippet_lang("commands[].command", "bash")];
    let input = json!({"commands": [{"command": "echo a"}, {"command": "echo b"}]})
        .as_object()
        .unwrap()
        .clone();

    let got = extract(&snippets, &input);

    assert_eq!(
        got,
        Extracted::Ok(vec![pair("echo a", "bash"), pair("echo b", "bash")])
    );
}

#[test]
fn nested_array_and_dotted_steps_combine() {
    let snippets = vec![snippet_lang("steps[].run.body", "bash")];
    let input = json!({"steps": [
        {"run": {"body": "echo a"}},
        {"run": {"body": "echo b"}},
    ]})
    .as_object()
    .unwrap()
    .clone();

    let got = extract(&snippets, &input);

    assert_eq!(
        got,
        Extracted::Ok(vec![pair("echo a", "bash"), pair("echo b", "bash")])
    );
}

#[test]
fn fixed_language_used_verbatim() {
    let snippets = vec![snippet_lang("code", "javascript")];
    let input = json!({"code": "console.log(1)"}).as_object().unwrap().clone();

    let got = extract(&snippets, &input);

    assert_eq!(got, Extracted::Ok(vec![pair("console.log(1)", "javascript")]));
}

#[test]
fn language_from_translates_through_language_values() {
    let snippets = vec![snippet_from(
        "code",
        "lang",
        &[("py", "python"), ("sh", "bash")],
    )];
    let input = json!({"code": "print(1)", "lang": "py"})
        .as_object()
        .unwrap()
        .clone();

    let got = extract(&snippets, &input);

    assert_eq!(got, Extracted::Ok(vec![pair("print(1)", "python")]));
}

#[test]
fn language_from_reads_top_level_even_when_field_is_nested() {
    // language_from names a sibling at the snippet declaration's ROOT — the
    // top-level input map — never a sibling nested alongside the field path.
    let snippets = vec![snippet_from("script.body", "lang", &[("py", "python")])];
    let input = json!({"script": {"body": "print(1)"}, "lang": "py"})
        .as_object()
        .unwrap()
        .clone();

    let got = extract(&snippets, &input);

    assert_eq!(got, Extracted::Ok(vec![pair("print(1)", "python")]));
}

#[test]
fn multiple_snippet_declarations_preserve_input_order() {
    let snippets = vec![snippet_lang("a", "python"), snippet_lang("b", "bash")];
    let input = json!({"a": "print(1)", "b": "echo hi"})
        .as_object()
        .unwrap()
        .clone();

    let got = extract(&snippets, &input);

    assert_eq!(
        got,
        Extracted::Ok(vec![pair("print(1)", "python"), pair("echo hi", "bash")])
    );
}

// ---------------------------------------------------------------------------
// language_from failures
// ---------------------------------------------------------------------------

#[test]
fn language_from_unmapped_value_refuses_naming_it() {
    let snippets = vec![snippet_from("code", "lang", &[("py", "python")])];
    let input = json!({"code": "print(1)", "lang": "ruby"})
        .as_object()
        .unwrap()
        .clone();

    let got = extract(&snippets, &input);

    assert_refused_naming(got, "ruby");
}

#[test]
fn language_from_missing_field_refuses() {
    let snippets = vec![snippet_from("code", "lang", &[("py", "python")])];
    let input = json!({"code": "print(1)"}).as_object().unwrap().clone();

    let got = extract(&snippets, &input);

    assert_refused_naming(got, "lang");
}

#[test]
fn language_from_non_string_field_refuses() {
    let snippets = vec![snippet_from("code", "lang", &[("py", "python")])];
    let input = json!({"code": "print(1)", "lang": 5})
        .as_object()
        .unwrap()
        .clone();

    let got = extract(&snippets, &input);

    assert_refused_naming(got, "lang");
}

// ---------------------------------------------------------------------------
// Field-path failures — every one names what was missing, and refuses the
// whole batch rather than deciding on a subset.
// ---------------------------------------------------------------------------

#[test]
fn missing_field_refuses_naming_it() {
    let snippets = vec![snippet_lang("script.body", "python")];
    let input = json!({"script": {}}).as_object().unwrap().clone();

    let got = extract(&snippets, &input);

    assert_refused_naming(got, "body");
}

#[test]
fn wrong_type_refuses_naming_field() {
    let snippets = vec![snippet_lang("script.body", "python")];
    let input = json!({"script": {"body": 42}}).as_object().unwrap().clone();

    let got = extract(&snippets, &input);

    assert_refused_naming(got, "body");
}

#[test]
fn empty_string_refuses() {
    let snippets = vec![snippet_lang("script.body", "python")];
    let input = json!({"script": {"body": ""}}).as_object().unwrap().clone();

    let got = extract(&snippets, &input);

    assert_refused_naming(got, "body");
}

#[test]
fn whitespace_only_string_refuses() {
    // A whitespace-only snippet is a no-op the same way an empty one is: if
    // it were let through, a whitespace-only bash string parses to zero
    // complete_commands, so decide_command_at never runs the guard/construct
    // checks and falls straight to a vacuous allow. The empty-string gate
    // must catch this too, not just the literal "".
    let snippets = vec![snippet_lang("script.body", "python")];
    let input = json!({"script": {"body": "  \n\t"}})
        .as_object()
        .unwrap()
        .clone();

    let got = extract(&snippets, &input);

    assert_refused_naming(got, "body");
}

#[test]
fn empty_array_refuses() {
    let snippets = vec![snippet_lang("commands[].command", "bash")];
    let input = json!({"commands": []}).as_object().unwrap().clone();

    let got = extract(&snippets, &input);

    assert_refused_naming(got, "commands");
}

#[test]
fn per_element_miss_refuses_whole_batch_not_a_subset() {
    let snippets = vec![snippet_lang("commands[].command", "bash")];
    let input = json!({"commands": [
        {"command": "echo a"},
        {"note": "no command field here"},
    ]})
    .as_object()
    .unwrap()
    .clone();

    let got = extract(&snippets, &input);

    // Not Ok(vec![("echo a", "bash")]) — a partial result is never returned.
    assert_refused_naming(got, "command");
}

#[test]
fn second_snippet_declaration_failing_refuses_whole_batch() {
    let snippets = vec![snippet_lang("a", "python"), snippet_lang("b", "bash")];
    let input = json!({"a": "print(1)"}).as_object().unwrap().clone();

    let got = extract(&snippets, &input);

    // The first declaration resolves fine; the batch still refuses because
    // the second does not.
    assert_refused_naming(got, "b");
}
