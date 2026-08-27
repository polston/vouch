use vouch::guards::{load, Knowledge, Program};
use vouch::knowledge::{merge, validate_text, KNOWLEDGE_SCHEMA_VERSION};

fn program<'a>(knowledge: &'a Knowledge, name: &str) -> &'a Program {
    knowledge
        .program
        .iter()
        .find(|program| {
            program
                .match_names
                .iter()
                .any(|candidate| candidate == name)
        })
        .expect("program entry exists")
}

#[test]
fn origin_claims_parse_as_optional_tag_lists() {
    let knowledge = load(
        "[[program]]\nmatch = [\"python:module.load\"]\nproduces = [\"data\"]\nreceiver_from = [\"file_handle\"]\n",
    )
    .expect("origin claims parse");
    let entry = program(&knowledge, "python:module.load");

    assert_eq!(entry.produces, Some(vec!["data".to_string()]));
    assert_eq!(entry.receiver_from, Some(vec!["file_handle".to_string()]));
}

#[test]
fn explicit_empty_origin_lists_retract_while_absence_preserves() {
    let base = load(
        "[[program]]\nmatch = [\"python:module.load\"]\nproduces = [\"data\"]\nreceiver_from = [\"file_handle\"]\n",
    )
    .expect("base parses");

    let absent = merge(
        base.clone(),
        load("[[program]]\nmatch = [\"python:module.load\"]\n").expect("overlay parses"),
    );
    assert_eq!(
        program(&absent, "python:module.load").produces,
        Some(vec!["data".to_string()])
    );
    assert_eq!(
        program(&absent, "python:module.load").receiver_from,
        Some(vec!["file_handle".to_string()])
    );

    let retracted = merge(
        base,
        load("[[program]]\nmatch = [\"python:module.load\"]\nproduces = []\nreceiver_from = []\n")
            .expect("retraction parses"),
    );
    assert_eq!(
        program(&retracted, "python:module.load").produces,
        Some(vec![])
    );
    assert_eq!(
        program(&retracted, "python:module.load").receiver_from,
        Some(vec![])
    );
}

#[test]
fn origin_tags_use_the_shared_ascii_identifier_grammar() {
    assert!(validate_text(
        "[[program]]\nmatch = [\"python:module.load\"]\nproduces = [\"data_2\"]\nreceiver_from = [\"_handle\"]\n"
    )
    .is_ok());

    for (field, invalid) in [("produces", "9data"), ("receiver_from", "file-handle")] {
        let error = validate_text(&format!(
            "[[program]]\nmatch = [\"python:module.load\"]\n{field} = [\"{invalid}\"]\n"
        ))
        .expect_err("invalid tag is refused");
        assert!(error.contains(field), "{error}");
        assert!(error.contains("valid identifier"), "{error}");
    }
}

#[test]
fn origin_claims_remain_available_after_schema_ten() {
    assert!(KNOWLEDGE_SCHEMA_VERSION >= 10);
}
