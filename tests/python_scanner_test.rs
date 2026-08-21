use vouch::python::parse;

mod common;

#[test]
fn the_registry_knows_python() {
    assert!(vouch::syntax::scanner_for("python").is_some());
}

// The per-command arrays stay parallel to `commands`. This scanner does not
// populate the input source — a python snippet's standard input is whatever
// the enclosing process was handed, so the answer belongs to the shell line
// above, not here — so every value is `Unknown`; the invariant under test is
// the length, not the content.
#[test]
fn the_per_command_arrays_stay_parallel_to_commands() {
    for src in ["print(1)", "import os\nos.remove('f')", "x = open('f'); x.read()"] {
        let p = parse(src).expect("scans");
        assert_eq!(p.input_source.len(), p.commands.len(), "input_source: {src}");
        assert_eq!(p.args_complete.len(), p.commands.len(), "args_complete: {src}");
    }
}

// --- API names stay in knowledge.toml, never in this scanner's code --------
//
// `src/python.rs`'s own module doc states the rule this test enforces: "NO
// API NAMES IN THIS FILE'S CODE" — what `shutil.rmtree` does is knowledge and
// lives in `knowledge.toml`, and a name embedded in `python.rs`'s SOURCE
// would be a rule that cannot be changed, inspected, or overridden without a
// rebuild. Nothing enforced that before this test. Scoped to `src/python.rs`
// ONLY — `src/guards.rs` legitimately carries the file-mode vocabulary
// ("mode", the mode charsets) as knowledge-DATA handling, and scanning it
// here would be a false positive, not a real leak.
//
// At this task the shipped knowledge has no `python:` match names yet (Task
// 11 ships them), so the loop below runs zero times and the test passes
// trivially — it is ARMED, not yet exercised by real data. The separate test
// below proves the underlying occurrence check actually distinguishes code
// from comments, so the armed-but-untested claim has evidence behind it.

/// Removes `//` line comments and `/* */` block comments from Rust source,
/// respecting string literals (so a `//` or `/*` written INSIDE a string
/// literal is not mistaken for a comment start). Not a full Rust tokenizer —
/// enough for a text scan whose only job is "was this name mentioned in
/// prose, or does it actually appear in executable-position code".
fn strip_rust_comments(src: &str) -> String {
    let mut out = String::with_capacity(src.len());
    let mut chars = src.chars().peekable();
    while let Some(c) = chars.next() {
        if c == '"' {
            // Copy the whole string literal verbatim, including any `//` or
            // `/*` inside it, and honor `\"` so an escaped quote does not end
            // the literal early.
            out.push(c);
            while let Some(c2) = chars.next() {
                out.push(c2);
                if c2 == '\\' {
                    if let Some(escaped) = chars.next() {
                        out.push(escaped);
                    }
                    continue;
                }
                if c2 == '"' {
                    break;
                }
            }
            continue;
        }
        if c == '/' && chars.peek() == Some(&'/') {
            for c2 in chars.by_ref() {
                if c2 == '\n' {
                    out.push('\n');
                    break;
                }
            }
            continue;
        }
        if c == '/' && chars.peek() == Some(&'*') {
            chars.next(); // consume the '*'
            let mut prev = ' ';
            for c2 in chars.by_ref() {
                if prev == '*' && c2 == '/' {
                    break;
                }
                prev = c2;
            }
            continue;
        }
        out.push(c);
    }
    out
}

/// Whether `name` appears anywhere in `src` OUTSIDE a comment, as a whole
/// word rather than a substring of something else.
///
/// A raw `.contains(name)` false-positived once real API names shipped:
/// `"eval"` is a substring of the construct name `"evaluated_input"`
/// (`src/python.rs`'s own `known_constructs` list), which is unrelated code,
/// not a hardcoded API name. Requiring a non-identifier character (or the
/// string edge) on both sides is what tells the two apart.
fn contains_as_literal(src: &str, name: &str) -> bool {
    if name.is_empty() {
        return false;
    }
    let stripped = strip_rust_comments(src);
    let is_ident = |c: char| c.is_alphanumeric() || c == '_';
    stripped.match_indices(name).any(|(idx, m)| {
        let before_ok = stripped[..idx].chars().next_back().map_or(true, |c| !is_ident(c));
        let after_ok = stripped[idx + m.len()..]
            .chars()
            .next()
            .map_or(true, |c| !is_ident(c));
        before_ok && after_ok
    })
}

/// Collects the CONTENTS of every string literal in `src` (comments already
/// stripped by the caller), dropping everything else — code, identifiers,
/// punctuation. Quote marks are not copied, and each literal's contents are
/// followed by a separator so two adjacent literals never blend into one
/// word (`"foo" "bar"` must not read as containing `foobar`). Escape
/// handling mirrors `strip_rust_comments`: `\"` does not end the literal
/// early, and the character following a backslash is copied as-is.
fn string_literal_contents(src: &str) -> String {
    let mut out = String::with_capacity(src.len());
    let mut chars = src.chars().peekable();
    while let Some(c) = chars.next() {
        if c == '"' {
            while let Some(c2) = chars.next() {
                if c2 == '\\' {
                    if let Some(escaped) = chars.next() {
                        out.push(escaped);
                    }
                    continue;
                }
                if c2 == '"' {
                    break;
                }
                out.push(c2);
            }
            out.push('\n');
        }
    }
    out
}

/// Whether `name` appears as a whole word INSIDE A STRING LITERAL in `src`,
/// with the `#[cfg(test)]` module (the file's tail in this codebase)
/// excluded from the scan. Unlike `contains_as_literal`, ordinary Rust code
/// — identifiers, method calls, `&str` types — never matches; only text
/// between quote marks does, which is the shape a knowledge-file name
/// leaking into a hardcoded match-arm string would actually take.
fn contains_as_shipped_name(src: &str, name: &str) -> bool {
    if name.is_empty() {
        return false;
    }
    let stripped = strip_rust_comments(src);
    let scanned = match stripped.find("#[cfg(test)]") {
        Some(idx) => &stripped[..idx],
        None => stripped.as_str(),
    };
    let contents = string_literal_contents(scanned);
    let is_ident = |c: char| c.is_alphanumeric() || c == '_';
    contents.match_indices(name).any(|(idx, m)| {
        let before_ok = contents[..idx]
            .chars()
            .next_back()
            .map_or(true, |c| !is_ident(c));
        let after_ok = contents[idx + m.len()..]
            .chars()
            .next()
            .map_or(true, |c| !is_ident(c));
        before_ok && after_ok
    })
}

#[test]
fn the_literal_occurrence_check_fires_on_code_and_not_on_comments() {
    // Proves the mechanism the api-names test below relies on actually
    // distinguishes "mentioned in code" from "mentioned only in prose",
    // independent of whatever the shipped knowledge currently contains.
    let in_code = "let x = \"shutil.rmtree\";\n";
    assert!(
        contains_as_literal(in_code, "shutil.rmtree"),
        "must fire when the name is a real string literal"
    );

    let in_line_comment = "// this module talks about shutil.rmtree in prose\nlet y = 1;\n";
    assert!(
        !contains_as_literal(in_line_comment, "shutil.rmtree"),
        "must NOT fire when the name only appears in a // comment"
    );

    let in_doc_comment = "/// explaining what shutil.rmtree does, in a block comment\nfn f() {}\n";
    assert!(
        !contains_as_literal(in_doc_comment, "shutil.rmtree"),
        "must NOT fire when the name only appears in a /* */ or /// comment"
    );
}

#[test]
fn a_real_comment_only_mention_in_python_rs_does_not_trip_the_check() {
    // Not a synthetic sample: `shutil.rmtree` genuinely appears several times
    // in python.rs's own doc comments (explaining the very "no API names in
    // code" rule this test enforces) and nowhere in its actual code. If
    // comment-stripping were broken, this specific real name is exactly what
    // would false-positive against the real file.
    let src = include_str!("../src/python.rs");
    assert!(
        src.contains("shutil.rmtree"),
        "test premise false: shutil.rmtree no longer appears in python.rs at all"
    );
    assert!(
        !contains_as_literal(src, "shutil.rmtree"),
        "shutil.rmtree only appears in python.rs's comments; the check must not fire on it"
    );
}

#[test]
fn a_name_in_ordinary_rust_code_is_not_a_leak() {
    // .len() is code, not a string literal — the reworked check must not fire.
    assert!(!contains_as_shipped_name("let n = args.len();", "len"));
}

#[test]
fn a_name_inside_a_string_literal_is_a_leak() {
    assert!(contains_as_shipped_name(r#"let s = "shutil.rmtree";"#, "shutil.rmtree"));
}

#[test]
fn the_test_module_is_excluded_from_the_scan() {
    let src = "fn a() {}\n#[cfg(test)]\nmod tests { const S: &str = \"len\"; }";
    assert!(!contains_as_shipped_name(src, "len"));
}

#[test]
fn shipped_python_api_names_never_appear_as_literals_in_the_scanner_source() {
    let kb = common::shipped_kb();
    let api_names: Vec<String> = kb
        .program
        .iter()
        .flat_map(|p| p.match_names.iter())
        .filter_map(|m| m.strip_prefix("python:"))
        .map(|m| m.trim_start_matches('.').to_string())
        .filter(|m| !m.is_empty())
        .collect();

    let src = include_str!("../src/python.rs");
    assert!(
        src.contains("#[cfg(test)]"),
        "test premise false: src/python.rs no longer has a #[cfg(test)] marker, \
         so the scan below cannot truncate before its test module and would \
         silently scan un-truncated"
    );
    let offenders: Vec<&String> = api_names
        .iter()
        .filter(|name| contains_as_shipped_name(src, name))
        .collect();

    assert!(
        offenders.is_empty(),
        "these python API names appear inside a string literal in src/python.rs, \
         which turns knowledge-file data into a hardcoded rule: {offenders:?}"
    );
}

#[test]
fn a_plain_call_becomes_a_prefixed_cmd() {
    let s = parse(r#"open("x.txt")"#).unwrap();
    assert_eq!(s.commands.len(), 1);
    assert_eq!(s.commands[0].head, "python:open");
    assert_eq!(s.commands[0].args, vec!["x.txt"]);
}

#[test]
fn a_dotted_module_call_keeps_the_module_path() {
    let s = parse("import os\nos.remove(\"f\")").unwrap();
    assert!(s
        .commands
        .iter()
        .any(|c| c.head == "python:os.remove" && c.args == vec!["f"]));
}

#[test]
fn an_unresolvable_argument_occupies_its_position() {
    // os.rename(compute(), "C:/x") — position 1 must still be the destination.
    let s = parse("import os\nos.rename(compute(), \"C:/x\")").unwrap();
    let c = s
        .commands
        .iter()
        .find(|c| c.head == "python:os.rename")
        .unwrap();
    assert_eq!(c.args, vec!["$?", "C:/x"]);
}

#[test]
fn keyword_arguments_carry_their_name() {
    let s = parse(r#"open(file="x", mode="w")"#).unwrap();
    let c = s.commands.iter().find(|c| c.head == "python:open").unwrap();
    assert_eq!(c.args, vec!["file=x", "mode=w"]);
}

#[test]
fn a_computed_callee_is_a_dynamic_call_construct() {
    let s = parse("d[\"k\"]()").unwrap();
    assert!(s.constructs.iter().any(|k| k == "dynamic_call"));
}

#[test]
fn a_parse_failure_is_err_never_an_empty_scan() {
    assert!(parse("def broken(:").is_err());
}

#[test]
fn indented_and_crlf_snippets_parse() {
    assert!(parse("    import os\r\n    os.getcwd()").is_ok());
}

#[test]
fn an_implicitly_concatenated_f_string_keeps_its_literal_prefix() {
    // "dir/" f"{d}.txt" is ONE Expr::FString value made of two PARTS: a
    // plain literal part and an f-string part. `FStringValue::elements()`
    // (what the module used before this fix) walks only the f-string
    // part's elements, so the plain "dir/" text is dropped with no marker
    // left behind — a stated value that is a silent truncation of the real
    // one.
    let s = parse(r#"open("dir/" f"{d}.txt")"#).unwrap();
    let c = s.commands.iter().find(|c| c.head == "python:open").unwrap();
    assert_eq!(c.args, vec!["dir/$d.txt"]);
}

#[test]
fn a_nameless_keyword_unpacking_leaves_a_marker() {
    // `**opts` is a `Keyword` node with `arg: None` — there is no name to
    // report a value under, but dropping it silently makes this call
    // indistinguishable from one that passed no keywords at all. Its own
    // sentinel, `"$**"` (task 2b fix round 2, roadmap M2.78) — distinct
    // from the ordinary unresolved-value marker `"$?"` — so a reader that
    // cares about the difference (`guards::callback_argument_used`) can
    // tell an unpack apart from an unresolvable value like `sys.stdin`,
    // which the two shared identically before this fix.
    let s = parse("open(p, **opts)").unwrap();
    let c = s.commands.iter().find(|c| c.head == "python:open").unwrap();
    assert_eq!(c.args, vec!["$p", "$**"]);
}

#[test]
fn a_variable_assigned_a_literal_resolves() {
    let s = parse("p = \"C:/work/x\"\nopen(p, \"w\")").unwrap();
    let c = s.commands.iter().find(|c| c.head == "python:open").unwrap();
    assert_eq!(c.args, vec!["C:/work/x", "w"]);
}

#[test]
fn an_import_alias_resolves_to_the_dotted_name() {
    let s = parse("import shutil as sh\nsh.rmtree(\"d\")").unwrap();
    assert!(s.commands.iter().any(|c| c.head == "python:shutil.rmtree"));
}

#[test]
fn a_from_import_resolves_the_bare_name() {
    let s = parse("from shutil import rmtree\nrmtree(\"d\")").unwrap();
    assert!(s.commands.iter().any(|c| c.head == "python:shutil.rmtree"));
}

#[test]
fn an_fstring_over_knowns_concatenates() {
    let s = parse("d = \"C:/out\"\nopen(f\"{d}/x.json\", \"w\")").unwrap();
    let c = s.commands.iter().find(|c| c.head == "python:open").unwrap();
    assert_eq!(c.args[0], "C:/out/x.json");
}

#[test]
fn plus_concatenation_of_literals_resolves() {
    let s = parse("d = \"C:/out\"\nopen(d + \"/x.json\", \"w\")").unwrap();
    let c = s.commands.iter().find(|c| c.head == "python:open").unwrap();
    assert_eq!(c.args[0], "C:/out/x.json");
}

#[test]
fn a_method_call_carries_its_receiver_as_argument_zero() {
    let s = parse("from pathlib import Path\nPath(\"C:/x\").write_text(\"hi\")").unwrap();
    let c = s
        .commands
        .iter()
        .find(|c| c.head == "python:.write_text")
        .unwrap();
    assert_eq!(c.args[0], "C:/x");
}

#[test]
fn an_unresolvable_receiver_is_a_marker_not_a_vanished_position() {
    // The reference branch dropped the receiver here, positions shifted,
    // and a writes="arg_0" entry had nothing to point at — a silent allow.
    let s = parse("p.mkdir()").unwrap();
    let c = s
        .commands
        .iter()
        .find(|c| c.head == "python:.mkdir")
        .unwrap();
    assert_eq!(c.args.len(), 1);
    assert!(
        c.args[0].starts_with('$'),
        "receiver must be a marker: {:?}",
        c.args
    );
}

#[test]
fn a_local_dict_method_is_a_method_not_a_module() {
    // `d.get(...)` with no `import d` must NOT become python:d.get —
    // the corpus has 621 snippets of `d.get` alone (branch census).
    let s = parse("d = {}\nd.get(\"k\")").unwrap();
    assert!(s.commands.iter().any(|c| c.head == "python:.get"));
    assert!(!s.commands.iter().any(|c| c.head == "python:d.get"));
}

#[test]
fn a_chained_method_calls_argument_is_not_mistaken_for_the_receiver() {
    // `p.with_suffix(".bak")` is a METHOD call, not a constructor: its one
    // string argument is a fragment the method transforms the receiver
    // with, not the receiver itself. Reading it as the receiver would
    // report a resolved-looking but wrong value (".bak" instead of the
    // actual, unresolvable, changed-suffix path).
    let s = parse("p.with_suffix(\".bak\").write_text(\"hi\")").unwrap();
    let c = s
        .commands
        .iter()
        .find(|c| c.head == "python:.write_text")
        .unwrap();
    assert_ne!(c.args[0], ".bak");
    assert!(
        c.args[0].starts_with('$'),
        "receiver must be a marker, not a fragment of the chain: {:?}",
        c.args
    );
}
