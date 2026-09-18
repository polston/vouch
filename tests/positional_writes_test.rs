//! Tests for positional-count-dependent program write destinations.

use vouch::guards::{load, written_paths_in, Knowledge};
use vouch::syntax::Cmd;

fn kb(text: &str) -> Knowledge {
    load(text).expect("fixture parses")
}

fn cmd(head: &str, args: &[&str]) -> Cmd {
    Cmd {
        head: head.into(),
        args: args.iter().map(|s| s.to_string()).collect(),
        unread_args: Default::default(),
        keyword_args: Default::default(),
        callable_args: Default::default(),
        chain: None,
        prefix_assigns: vec![],
        env_assigns: Default::default(),
        receiver_origin: vouch::syntax::ValueOrigin::Unknown,
        by_reference: false,
        is_intra_command_function: false,
        expandable_args: Default::default(),
    }
}

#[test]
fn positional_writes_with_min_threshold() {
    let k = kb(r#"
version = 17
[[program]]
match = ["myfilter"]
writes = "positional"
min_positional_write = 2
"#);

    // 1 positional: clean read, no written path extracted
    let c1 = cmd("myfilter", &["input.bin"]);
    let wt1 = written_paths_in(&k, &c1, "bash");
    assert_eq!(wt1.paths, Vec::<String>::new());

    // 2 positionals: threshold met, default last positional is destination
    let c2 = cmd("myfilter", &["input.bin", "output.hex"]);
    let wt2 = written_paths_in(&k, &c2, "bash");
    assert_eq!(wt2.paths, vec!["output.hex"]);

    // 3 positionals: last is destination
    let c3 = cmd("myfilter", &["a.bin", "b.bin", "c.hex"]);
    let wt3 = written_paths_in(&k, &c3, "bash");
    assert_eq!(wt3.paths, vec!["c.hex"]);
}

#[test]
fn positional_writes_takes_first() {
    let k = kb(r#"
version = 17
[[program]]
match = ["myconverter"]
writes = "positional"
min_positional_write = 2
positional_write_takes = "first"
"#);

    // 1 positional: below threshold
    let c1 = cmd("myconverter", &["input.bin"]);
    let wt1 = written_paths_in(&k, &c1, "bash");
    assert_eq!(wt1.paths, Vec::<String>::new());

    // 2 positionals: threshold met, first positional is destination
    let c2 = cmd("myconverter", &["output.hex", "input.bin"]);
    let wt2 = written_paths_in(&k, &c2, "bash");
    assert_eq!(wt2.paths, vec!["output.hex"]);
}

#[test]
fn last_arg_writes_respects_min_positional_write() {
    let k = kb(r#"
version = 17
[[program]]
match = ["xxd_like"]
writes = "last_arg"
min_positional_write = 2
"#);

    let c1 = cmd("xxd_like", &["input.bin"]);
    let wt1 = written_paths_in(&k, &c1, "bash");
    assert_eq!(wt1.paths, Vec::<String>::new());

    let c2 = cmd("xxd_like", &["input.bin", "output.hex"]);
    let wt2 = written_paths_in(&k, &c2, "bash");
    assert_eq!(wt2.paths, vec!["output.hex"]);
}

#[test]
fn named_writes_positional_fallback_respects_min_positional_write() {
    let k = kb(r#"
version = 17
[[program]]
match = ["named_tool"]
writes = "named"
write_flags = ["-o", "--output"]
value_options = ["-o", "--output"]
min_positional_write = 2
"#);

    // 1 positional with no flag: below threshold
    let c1 = cmd("named_tool", &["input.bin"]);
    let wt1 = written_paths_in(&k, &c1, "bash");
    assert_eq!(wt1.paths, Vec::<String>::new());

    // 2 positionals with no flag: fallback kicks in and extracts destination
    let c2 = cmd("named_tool", &["input.bin", "output.hex"]);
    let wt2 = written_paths_in(&k, &c2, "bash");
    assert_eq!(wt2.paths, vec!["output.hex"]);

    // Write flag used: extracts from flag regardless of positional count
    let c3 = cmd("named_tool", &["-o", "flag_out.hex", "input.bin"]);
    let wt3 = written_paths_in(&k, &c3, "bash");
    assert_eq!(wt3.paths, vec!["flag_out.hex"]);
}

#[test]
fn invalid_positional_write_takes_is_rejected() {
    let res = vouch::knowledge::validate_text(r#"
version = 17
[[program]]
match = ["bad_tool"]
writes = "positional"
positional_write_takes = "middle"
"#);
    assert!(res.is_err(), "should reject invalid positional_write_takes");
    let err = res.unwrap_err();
    assert!(err.contains("positional_write_takes"), "error should name positional_write_takes: {err}");
}
