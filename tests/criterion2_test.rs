//! Criterion 2, checked as a whole: EVERY construct has a working setting.
//!
//! Individual constructs have been tested since the beginning, but the
//! criterion is a claim about the SET — that nothing vouch can stop on is
//! unturnoffable. That had never been checked exhaustively, so a construct
//! added by the engine rather than a scanner could have slipped through with
//! no setting behind it and nothing would have failed.
//!
//! These tests enumerate the names from the scanners themselves, so a new
//! construct is covered the moment it is added rather than when someone
//! remembers to write a test for it.

use vouch::config::{load, Action, Config};
use vouch::engine::decide_command_in;
use vouch::protocol::Decision;
use vouch::syntax::{scanner_for, scanner_languages};

/// Every settable construct name, per language, taken from the scanners.
fn all_constructs() -> Vec<(&'static str, Vec<String>)> {
    scanner_languages()
        .map(|lang| {
            let names = scanner_for(lang)
                .expect("scanner exists")
                .known_constructs()
                .iter()
                .map(|s| s.to_string())
                .collect();
            (lang, names)
        })
        .collect()
}

fn cfg_with(lang: &str, name: &str, action: &str) -> Config {
    load(&format!(
        "version = 1\n[lang.{lang}]\ndefault = \"allow\"\n\
         [lang.{lang}.constructs]\n{name} = \"{action}\"\n"
    ))
    .expect("config parses")
}

#[test]
fn every_construct_name_is_settable_to_each_action() {
    // The setting must be READ BACK as what was written. A name the config
    // loader silently drops would leave a prompt with no way to turn it off,
    // which is the entire complaint this project exists to answer.
    for (lang, names) in all_constructs() {
        assert!(!names.is_empty(), "{lang} reported no constructs");
        for name in &names {
            for (text, want) in [
                ("allow", Action::Allow),
                ("ask", Action::Ask),
                ("deny", Action::Deny),
            ] {
                let cfg = cfg_with(lang, name, text);
                assert_eq!(
                    cfg.construct_action(lang, name),
                    want,
                    "lang.{lang}.constructs.{name} = \"{text}\" did not take effect"
                );
            }
        }
    }
}

#[test]
fn an_unset_construct_never_silently_allows() {
    // The default for anything vouch cannot see through is Ask, never Allow.
    // A permissive default is how the absence of knowledge becomes permission.
    let cfg = load("version = 1\n[lang.bash]\ndefault = \"allow\"\n").expect("parses");
    for (lang, names) in all_constructs() {
        for name in &names {
            assert_eq!(
                cfg.construct_action(lang, name),
                Action::Ask,
                "lang.{lang}.constructs.{name} defaulted to something other than Ask"
            );
        }
    }
}

#[test]
fn every_construct_name_appears_in_its_own_prompt() {
    // A prompt that does not name its setting cannot be turned off, however
    // real the setting is. The reason text must carry the key.
    for (lang, names) in all_constructs() {
        for name in &names {
            let reason = vouch::engine::construct_reason_for(lang, name);
            assert!(
                reason.contains(&format!("lang.{lang}.constructs.{name}")),
                "the prompt for {lang}/{name} does not name its setting:\n{reason}"
            );
        }
    }
}

#[test]
fn every_construct_has_a_plain_language_description() {
    // "vouch recognises this but cannot follow what it does" is the fallback.
    // Every name should say something more useful than that.
    let mut vague = Vec::new();
    for (lang, names) in all_constructs() {
        for name in &names {
            let reason = vouch::engine::construct_reason_for(lang, name);
            if reason.contains("recognises this but cannot follow") {
                vague.push(format!("{lang}/{name}"));
            }
        }
    }
    assert!(
        vague.is_empty(),
        "these constructs have no description of their own: {vague:?}"
    );
}

#[test]
fn setting_a_construct_to_allow_actually_stops_the_prompt() {
    // The end-to-end version: a command that trips a construct, with that
    // construct allowed, must not prompt because of it.
    let cases: &[(&str, &str, &str)] = &[
        ("bash", "heredoc", "cat << EOF\nhi\nEOF"),
        ("bash", "subshell", "echo $(date)"),
        ("bash", "function_def", "f() { echo hi; }"),
        ("bash", "background", "sleep 1 &"),
        ("powershell", "type_literal", "[System.IO.Path]::GetTempPath()"),
        ("powershell", "keyword_foreach", "foreach ($i in 1..3) { $i }"),
        ("powershell", "call_operator", "& \"C:/work/x.exe\""),
        ("powershell", "splatting", "Get-ChildItem @params"),
    ];
    for (lang, name, cmd) in cases {
        // Allow everything else too, so an Ask can only come from `name`.
        // Built by filtering, because listing the extras literally duplicates
        // whichever key is under test and TOML refuses a duplicate.
        let extras: String = [
            "unmodeled_command",
            "subshell",
            "assignment",
            "dynamic_command",
            "method_call",
            "env_assignment",
            "redirect",
            "heredoc",
            "background",
            "function_def",
        ]
        .iter()
        .filter(|k| *k != name)
        .map(|k| format!("{k} = \"allow\"\n"))
        .collect();
        let cfg = load(&format!(
            "version = 1\n[lang.{lang}]\ndefault = \"allow\"\n[lang.{lang}.constructs]\n\
             {name} = \"allow\"\n{extras}"
        ))
        .expect("parses");
        let d = decide_command_in(&cfg, lang, cmd, Some("C:/Users/dev"), None);
        if let Decision::Ask(r) = &d {
            assert!(
                !r.contains(&format!("stopped on: {name}")),
                "lang.{lang}.constructs.{name} = allow did not stop the prompt:\n{r}"
            );
        }
    }
}

/// Every construct name that appears anywhere in the engine or the scanners.
///
/// Read from the SOURCE, not from `known_constructs()`. The list-driven tests
/// above cannot catch a construct the engine emits that was never added to the
/// scanner's list — which is exactly the failure they exist to prevent, and
/// three of the current names (`unresolved_path`, `evaluated_input`,
/// `splatting`) are engine-emitted and were added to those lists by hand.
/// Every `"<name>"` immediately following `<call_prefix><ident>, "` in `src`,
/// where `<ident>` is WHICHEVER local binding the call site uses for its
/// language key — `lang`, `clang`, `ckey`, `plang`, or any future spelling.
/// Hardcoding one spelling was already wrong once (the offset-by-one bug the
/// comment on `names_in_source` used to record): a legitimate rename at a
/// call site — `construct_reason(lang, "unresolved_path")` becoming
/// `construct_reason(clang, "unresolved_path")` to key the prompt to the
/// OCCURRENCE rather than the host (M2.79) — must not silently drop that
/// site's name from the set this test exists to find. The identifier's own
/// spelling is not part of what makes a name "engine-emitted"; only the call
/// shape is.
fn find_after_ident_arg(src: &str, call_prefix: &str, out: &mut Vec<String>) {
    let mut rest = src;
    while let Some(i) = rest.find(call_prefix) {
        let after = &rest[i + call_prefix.len()..];
        let ident_len =
            after.find(|c: char| !(c.is_ascii_alphanumeric() || c == '_')).unwrap_or(0);
        if let Some(tail) = after[ident_len..].strip_prefix(", \"") {
            if let Some(end) = tail.find('"') {
                let name = &tail[..end];
                if !name.is_empty()
                    && name.chars().all(|c| c.is_ascii_lowercase() || c == '_')
                    && !out.contains(&name.to_string())
                {
                    out.push(name.to_string());
                }
            }
        }
        // Advance past the matched prefix at minimum, so a `call_prefix`
        // match with no valid identifier after it (a false hit inside a
        // comment or a different call shape) still makes progress. A flat
        // byte offset of 1 is not always a char boundary — the character
        // right after the prefix can be multi-byte, such as an em dash in a
        // doc comment — so the fallback step is that character's own byte
        // length, never a fixed 1.
        let advance = if ident_len > 0 {
            ident_len
        } else {
            after.chars().next().map(char::len_utf8).unwrap_or(1)
        };
        rest = &after[advance.min(after.len())..];
    }
}

fn names_in_source() -> Vec<String> {
    let mut out = Vec::new();
    for src in [
        include_str!("../src/engine.rs"),
        include_str!("../src/shell.rs"),
        include_str!("../src/powershell.rs"),
        include_str!("../src/python.rs"),
    ] {
        let mut rest = src;
        while let Some(i) = rest.find("note(\"") {
            let after = &rest[i + "note(\"".len()..];
            if let Some(end) = after.find('"') {
                let name = &after[..end];
                if !name.is_empty()
                    && name.chars().all(|c| c.is_ascii_lowercase() || c == '_')
                    && !out.contains(&name.to_string())
                {
                    out.push(name.to_string());
                }
            }
            rest = &rest[i + "note(\"".len()..];
        }
        find_after_ident_arg(src, "construct_action_for(cfg, ", &mut out);
        find_after_ident_arg(src, "construct_reason(", &mut out);
    }
    out
}

#[test]
fn no_construct_is_emitted_that_the_scanners_do_not_declare() {
    // If this fails, a prompt exists that the settable-name tests never see.
    let declared: Vec<String> = scanner_languages()
        .flat_map(|l| {
            scanner_for(l)
                .expect("scanner")
                .known_constructs()
                .iter()
                .map(|s| s.to_string())
                .collect::<Vec<_>>()
        })
        .collect();

    let missing: Vec<&String> = names_in_source()
        .iter()
        .filter(|n| !declared.contains(n))
        .cloned()
        .collect::<Vec<String>>()
        .leak()
        .iter()
        .collect();

    assert!(
        missing.is_empty(),
        "these construct names are emitted but not declared by any scanner, so \
         nothing verifies they have a working setting: {missing:?}"
    );
}

#[test]
fn the_scanner_registry_is_unique_and_matches_each_scanner() {
    let languages: Vec<_> = scanner_languages().collect();
    assert!(!languages.is_empty(), "the scanner registry is empty");
    assert!(
        languages.iter().all(|lang| !lang.is_empty()),
        "the scanner registry contains an empty language name: {languages:?}"
    );

    let unique: std::collections::HashSet<_> = languages.iter().copied().collect();
    assert_eq!(
        unique.len(),
        languages.len(),
        "the scanner registry contains duplicate language names: {languages:?}"
    );

    for lang in languages {
        let scanner = scanner_for(lang).expect("every registration resolves");
        assert_eq!(scanner.lang(), lang, "registration and scanner disagree");
    }
    assert!(scanner_for("not-a-vouch-language").is_none());
}

#[test]
fn the_source_scan_actually_finds_names() {
    // A scan that silently found nothing would make the test above pass
    // vacuously — which is worse than not having it.
    let found = names_in_source();
    assert!(
        found.len() >= 15,
        "the source scan found only {} names, so the coverage check above \
         proves nothing: {found:?}",
        found.len()
    );
    for expect in ["unresolved_path", "evaluated_input", "splatting", "heredoc"] {
        assert!(
            found.iter().any(|n| n == expect),
            "source scan missed '{expect}': {found:?}"
        );
    }
}

#[test]
fn find_after_ident_arg_does_not_panic_on_a_multi_byte_character() {
    // A `call_prefix` match immediately followed by a multi-byte character
    // (an em dash, as this codebase's own comments use) used to panic: the
    // fallback advance was a flat byte offset of 1, which is not a char
    // boundary partway through a multi-byte encoding.
    let mut out = Vec::new();
    find_after_ident_arg("construct_reason(— \"x\")", "construct_reason(", &mut out);
    assert!(out.is_empty(), "no valid identifier arg here: {out:?}");

    // A real match must still be found on the far side of such a character.
    let mut out = Vec::new();
    find_after_ident_arg(
        "// construct_reason(—) construct_reason(lang, \"unresolved_path\")",
        "construct_reason(",
        &mut out,
    );
    assert_eq!(out, vec!["unresolved_path".to_string()]);
}
