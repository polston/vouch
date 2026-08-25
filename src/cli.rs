//! Argument parsing for `vouch explain` and `vouch why`, and the
//! `vouch schema` verb (argument parsing plus the reference-doc renderer).
//!
//! Pure on purpose: no config, no I/O, no `process::exit`. The previous
//! version of this logic was inline in `main.rs`, could only be exercised by
//! spawning the binary, and was wrong for a shape nobody tested —
//! `explain bash '<cmd>'` explained the one-word command `bash`.
//!
//! Note the language names here are vouch's own vocabulary for its scanners,
//! not knowledge about the world. In real operation nothing parses a selector
//! at all: the tool's own `[[tool.snippet]]` declaration in knowledge.toml
//! names the language (`route::decide_snippet`), read off the harness's own
//! report of which tool ran. A selector exists only for the manual commands,
//! where there is no tool call to read that from.

/// What to explain, in which language, and from which directory if the
/// caller said one.
#[derive(Debug, PartialEq, Eq)]
pub struct Target {
    pub lang: &'static str,
    pub cmd: String,
    /// Set only by `--cwd <dir>`. `None` means "the caller decides what
    /// directory to fall back to" — `explain` uses the process's own
    /// working directory; this module has no opinion on that, the same way
    /// it has none about which language `bash` defaults to being reasoned
    /// about further up.
    pub cwd: Option<String>,
}

fn selector(s: &str) -> Option<&'static str> {
    match s {
        "ps" | "powershell" => Some("powershell"),
        "bash" | "sh" => Some("bash"),
        _ => None,
    }
}

/// Parse the arguments AFTER the subcommand word.
///
/// `--cwd <dir>` is consumed first, if present, before anything positional is
/// looked at — it is not one of the positionals itself, so `vouch explain
/// --cwd C:/scratch/j git status` and `vouch explain git status` disagree only
/// about `cwd`, never about `lang`/`cmd`.
///
/// `["bash", "ls -la"]` -> bash, `ls -la`
/// `["ls -la"]`         -> bash, `ls -la`
/// `["ps"]`             -> bash, `ps`   (a lone selector is a command: `ps`
///                                      and `bash` are real programs, and
///                                      asking about them must stay possible)
/// `[]`                 -> bash, ``     (callers treat empty as "no argument")
///
/// Anything else is an error rather than a guess. Guessing is what produced
/// the defect this function replaces.
pub fn parse_target(args: &[String]) -> Result<Target, String> {
    const USAGE: &str = "usage: vouch explain [--cwd <dir>] [bash|ps] '<command>'\n  \
                         the command must be ONE argument - quote it, e.g. \
                         vouch explain 'rm -rf /tmp/x'";
    let (cwd, positional) = match args {
        [flag] if flag == "--cwd" => {
            return Err(format!("vouch: --cwd needs a directory.\n{USAGE}"));
        }
        [flag, value, rest @ ..] if flag == "--cwd" => (Some(value.clone()), rest),
        _ => (None, args),
    };
    match positional {
        [] => Ok(Target { lang: "bash", cmd: String::new(), cwd }),
        [only] => Ok(Target { lang: "bash", cmd: only.clone(), cwd }),
        [first, rest] => match selector(first) {
            Some(lang) => Ok(Target { lang, cmd: rest.clone(), cwd }),
            None => Err(format!(
                "vouch: '{first}' is not a language selector, and a command must be \
                 one argument.\n{USAGE}"
            )),
        },
        _ => Err(format!(
            "vouch: too many arguments - a command must be one argument.\n{USAGE}"
        )),
    }
}

// --- `vouch schema <config|knowledge> [--write]` ---------------------------
//
// The generated schema docs exist so `config.toml` and `knowledge.toml` have
// a reference that cannot drift from what the loaders actually accept: both
// the JSON Schema files and the human page below are produced from the same
// `Raw` and `Knowledge` structs the real loaders deserialize into
// (`config::json_schema`, `guards::json_schema`), never hand-maintained.

/// Which schema `vouch schema` was asked to print — only meaningful for the
/// no-`--write` (stdout) path; `--write` always regenerates the complete set
/// (both schema files and the combined reference page) regardless of which
/// one was named, because the page documents both and a partial regenerate
/// would leave it describing one struct current and the other stale.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum SchemaTarget {
    Config,
    Knowledge,
}

pub type InstallHost = crate::protocol::Host;

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum InstallShell {
    Bash,
    PowerShell,
}

impl InstallShell {
    pub fn as_str(self) -> &'static str {
        match self {
            Self::Bash => "bash",
            Self::PowerShell => "powershell",
        }
    }

    fn parse(value: &str) -> Result<Self, String> {
        match value {
            "bash" => Ok(Self::Bash),
            "powershell" | "ps" => Ok(Self::PowerShell),
            other => Err(format!(
                "vouch: unknown shell {other:?}; expected bash or powershell"
            )),
        }
    }
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct HookOptions {
    pub host: InstallHost,
    pub shell: Option<InstallShell>,
    pub shadow: bool,
    pub state_dir: Option<String>,
}

/// A hook command runs from the session cwd, so a relative state directory
/// would split one logical journal across whatever repositories Codex visits.
/// Accept both native absolute spellings independent of the platform running
/// the test suite; generated Windows registrations are tested on Unix too.
pub fn validate_state_dir(value: &str) -> Result<(), String> {
    let b = value.as_bytes();
    let unix = value.starts_with('/');
    let drive = b.len() >= 3
        && b[0].is_ascii_alphabetic()
        && b[1] == b':'
        && matches!(b[2], b'/' | b'\\');
    let unc = value.starts_with("\\\\");
    if value.is_empty()
        || value.contains('\r')
        || value.contains('\n')
        || !(unix || drive || unc)
    {
        return Err(format!(
            "vouch: --state-dir must be an absolute path, got {value:?}"
        ));
    }
    Ok(())
}

pub fn parse_hook_options(args: &[String]) -> Result<HookOptions, String> {
    let mut host = InstallHost::Claude;
    let mut shell = None;
    let mut shadow = false;
    let mut state_dir = None;
    let mut i = 0;
    while i < args.len() {
        match args[i].as_str() {
            "--hook" => {}
            "--shadow" => shadow = true,
            "--host" | "--shell" | "--state-dir" if i + 1 == args.len() => {
                return Err(format!("vouch: {} needs a value", args[i]));
            }
            "--host" => {
                host = InstallHost::parse(&args[i + 1])?;
                i += 1;
            }
            "--shell" => {
                shell = Some(InstallShell::parse(&args[i + 1])?);
                i += 1;
            }
            "--state-dir" => {
                validate_state_dir(&args[i + 1])?;
                state_dir = Some(args[i + 1].clone());
                i += 1;
            }
            other => return Err(format!("vouch: unrecognised hook flag {other:?}")),
        }
        i += 1;
    }
    match (host, shell, state_dir.is_some()) {
        (InstallHost::Codex, None, _) => {
            Err("vouch: Codex hook needs --shell bash or --shell powershell".into())
        }
        (InstallHost::Claude, Some(_), _) => {
            Err("vouch: --shell is only meaningful with --host codex".into())
        }
        (InstallHost::Claude, None, true) => {
            Err("vouch: --state-dir is only meaningful with --host codex".into())
        }
        _ => Ok(HookOptions {
            host,
            shell,
            shadow,
            state_dir,
        }),
    }
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct InstallOptions {
    pub host: InstallHost,
    pub shell: Option<InstallShell>,
    pub shadow: bool,
    pub hooks_only: bool,
    pub state_dir: Option<String>,
}

/// Parse the complete cross-host install interface without reading either
/// host's settings. A shell is explicit for Codex because its canonical
/// `Bash` hook name does not identify the shell that executes the command.
pub fn parse_install_options(args: &[String]) -> Result<InstallOptions, String> {
    const USAGE: &str =
        "usage: vouch install [--host claude|codex] [--shell bash|powershell] [--state-dir <absolute>] [--shadow] [--print]";
    let mut host = InstallHost::Claude;
    let mut shell = None;
    let mut shadow = false;
    let mut hooks_only = false;
    let mut state_dir = None;
    let mut i = 0;
    while i < args.len() {
        match args[i].as_str() {
            "--shadow" => shadow = true,
            "--print" => hooks_only = true,
            "--host" | "--shell" | "--state-dir" if i + 1 == args.len() => {
                return Err(format!("vouch: {} needs a value.\n{USAGE}", args[i]));
            }
            "--host" => {
                host = InstallHost::parse(&args[i + 1])?;
                i += 1;
            }
            "--shell" => {
                shell = Some(InstallShell::parse(&args[i + 1])?);
                i += 1;
            }
            "--state-dir" => {
                validate_state_dir(&args[i + 1])?;
                state_dir = Some(args[i + 1].clone());
                i += 1;
            }
            other => {
                return Err(format!(
                    "vouch: '{other}' is not a recognised install flag.\n{USAGE}"
                ));
            }
        }
        i += 1;
    }
    match (host, shell, state_dir.is_some()) {
        (InstallHost::Codex, None, _) => Err(format!(
            "vouch: Codex installation needs --shell bash or --shell powershell.\n{USAGE}"
        )),
        (InstallHost::Claude, Some(_), _) => Err(format!(
            "vouch: --shell is only meaningful with --host codex.\n{USAGE}"
        )),
        (InstallHost::Claude, None, true) => Err(format!(
            "vouch: --state-dir is only meaningful with --host codex.\n{USAGE}"
        )),
        _ => Ok(InstallOptions { host, shell, shadow, hooks_only, state_dir }),
    }
}

/// Parse the arguments after `vouch install`. Returns `(shadow, hooks_only)`.
/// Any argument other than the two recognised flags is refused here, before
/// the caller reads `settings.json` or prints anything — an unrecognised
/// argument (a typo, or a flag from a different command) must never fall
/// through to the bare-install form and print more than was asked for.
pub fn parse_install_args(args: &[String]) -> Result<(bool, bool), String> {
    let options = parse_install_options(args)?;
    Ok((options.shadow, options.hooks_only))
}

/// Parse the arguments after `vouch schema`.
pub fn parse_schema_args(args: &[String]) -> Result<(SchemaTarget, bool), String> {
    const USAGE: &str = "usage: vouch schema <config|knowledge> [--write]";
    let write = args.iter().any(|a| a == "--write");
    let positional: Vec<&String> = args.iter().filter(|a| a.as_str() != "--write").collect();
    match positional.as_slice() {
        [t] if t.as_str() == "config" => Ok((SchemaTarget::Config, write)),
        [t] if t.as_str() == "knowledge" => Ok((SchemaTarget::Knowledge, write)),
        [] => Err(format!(
            "vouch: schema needs a target, 'config' or 'knowledge'.\n{USAGE}"
        )),
        [t] => Err(format!(
            "vouch: '{t}' is not 'config' or 'knowledge'.\n{USAGE}"
        )),
        _ => Err(format!("vouch: too many arguments.\n{USAGE}")),
    }
}

/// The complete generated doc set: the two schema JSON texts and the human
/// reference page built from both. Always produced together — see
/// `SchemaTarget`'s doc comment for why a partial write is not offered.
pub struct GeneratedSchemaDocs {
    pub config_json: String,
    pub knowledge_json: String,
    pub reference_md: String,
}

/// Generate the complete doc set from the live structs. The one function
/// both the `schema` verb and the drift test call, so "what the binary would
/// write" and "what the test compares against" can never be two
/// independently-written answers to the same question.
pub fn generate_schema_docs() -> GeneratedSchemaDocs {
    let config_schema = crate::config::json_schema();
    let knowledge_schema = crate::guards::json_schema();
    let config_json = serde_json::to_string_pretty(&config_schema).unwrap_or_default();
    let knowledge_json = serde_json::to_string_pretty(&knowledge_schema).unwrap_or_default();
    let reference_md = render_reference_md(
        &serde_json::to_value(&config_schema).unwrap_or_default(),
        &serde_json::to_value(&knowledge_schema).unwrap_or_default(),
    );
    GeneratedSchemaDocs {
        config_json,
        knowledge_json,
        reference_md,
    }
}

/// The name at the end of a `"#/$defs/TypeName"` reference.
fn ref_name(r: &str) -> String {
    r.rsplit('/').next().unwrap_or(r).to_string()
}

/// A plain-language type label for one property's schema fragment: `array of
/// string`, `map of string to Action`, `integer (optional)`, a `$ref`'d type
/// name, or `A or B` for a schemars-emitted `anyOf`.
fn type_label(schema: &serde_json::Value) -> String {
    if let Some(r) = schema.get("$ref").and_then(|v| v.as_str()) {
        return ref_name(r);
    }
    if let Some(any_of) = schema.get("anyOf").and_then(|v| v.as_array()) {
        // The shape schemars emits for `Option<T>` when T is itself a `$ref`
        // (an enum or nested struct): `anyOf: [{"$ref": ...}, {"type":
        // "null"}]`, rather than folding `null` into an inline `type` array
        // the way it does for `Option` of a primitive. Read the same as that
        // primitive case — "T (optional)" — instead of joining literally into
        // "T or any (optional)".
        let is_null_branch =
            |b: &serde_json::Value| b.get("type").and_then(|t| t.as_str()) == Some("null");
        let optional = any_of.iter().any(is_null_branch);
        let parts: Vec<String> = any_of
            .iter()
            .filter(|b| !is_null_branch(b))
            .map(type_label)
            .collect();
        let base = if parts.is_empty() {
            "any".to_string()
        } else {
            parts.join(" or ")
        };
        return if optional {
            format!("{base} (optional)")
        } else {
            base
        };
    }
    let Some(ty) = schema.get("type") else {
        return "any".to_string();
    };
    let types: Vec<&str> = match ty {
        serde_json::Value::String(s) => vec![s.as_str()],
        serde_json::Value::Array(a) => a.iter().filter_map(|v| v.as_str()).collect(),
        _ => vec![],
    };
    let optional = types.contains(&"null");
    let base = match types.iter().find(|t| **t != "null") {
        Some(&"array") => {
            let item = schema
                .get("items")
                .map(type_label)
                .unwrap_or_else(|| "any".to_string());
            format!("array of {item}")
        }
        Some(&"object") => match schema.get("additionalProperties") {
            Some(ap) if ap.is_object() => format!("map of string to {}", type_label(ap)),
            _ => "object".to_string(),
        },
        Some(t) => t.to_string(),
        None => "any".to_string(),
    };
    if optional {
        format!("{base} (optional)")
    } else {
        base
    }
}

/// A schema property's own JSON serialized compactly, for the reference
/// table's Default column.
fn compact_json(v: &serde_json::Value) -> String {
    serde_json::to_string(v).unwrap_or_default()
}

/// The Default column for one property: `(required)` when the containing
/// object's `required` list names it, `(unset)` when its declared default is
/// JSON null (an `Option` field defaulting to `None`), `(none)` when
/// schemars recorded no default at all, otherwise the default value itself.
fn default_label(schema: &serde_json::Value, required: bool) -> String {
    if required {
        return "(required)".to_string();
    }
    match schema.get("default") {
        None => "(none)".to_string(),
        Some(serde_json::Value::Null) => "(unset)".to_string(),
        Some(v) => compact_json(v),
    }
}

/// One line's worth of description text: a schema `description` is the doc
/// comment verbatim, which may run to several lines — a markdown table cell
/// cannot hold a literal newline, so this folds it to one line and escapes
/// the one character (`|`) that would otherwise split the cell.
fn table_cell_text(s: &str) -> String {
    s.replace('\n', " ").replace('|', "\\|")
}

/// A field table for one object schema fragment (a root schema or one
/// `$defs` entry) — empty string when the fragment has no `properties` at
/// all (an enum's `$defs` entry, handled separately by `render_enum_table`).
fn render_object_table(obj: &serde_json::Value) -> String {
    let Some(props) = obj.get("properties").and_then(|v| v.as_object()) else {
        return String::new();
    };
    let required: std::collections::BTreeSet<&str> = obj
        .get("required")
        .and_then(|v| v.as_array())
        .map(|a| a.iter().filter_map(|v| v.as_str()).collect())
        .unwrap_or_default();
    // `serde_json::Map` without the `preserve_order` feature is a `BTreeMap`
    // and already iterates alphabetically — sorted again explicitly so this
    // renderer's determinism (load-bearing for the drift test) does not rest
    // on that feature staying off somewhere upstream.
    let mut names: Vec<&String> = props.keys().collect();
    names.sort();
    let mut out = String::from("| Field | Type | Default | Description |\n|---|---|---|---|\n");
    for name in names {
        let schema = &props[name];
        let ty = type_label(schema);
        let def = default_label(schema, required.contains(name.as_str()));
        let desc = table_cell_text(
            schema
                .get("description")
                .and_then(|v| v.as_str())
                .unwrap_or(""),
        );
        out.push_str(&format!("| `{name}` | {ty} | {def} | {desc} |\n"));
    }
    out.push('\n');
    out
}

/// A variant list for one enum `$defs` entry (schemars emits a closed enum
/// like `Action` as `oneOf` over `const` values) — empty string when the
/// fragment is not shaped like one.
fn render_enum_table(def: &serde_json::Value) -> String {
    let Some(one_of) = def.get("oneOf").and_then(|v| v.as_array()) else {
        return String::new();
    };
    let mut out = String::new();
    for variant in one_of {
        let cnst = variant.get("const").and_then(|c| c.as_str()).unwrap_or("");
        let desc = variant
            .get("description")
            .and_then(|d| d.as_str())
            .unwrap_or("");
        out.push_str(&format!("- `{cnst}` — {desc}\n"));
    }
    out.push('\n');
    out
}

/// One root schema, rendered as a titled section: its own description, a
/// "Top level" table for its direct fields, then one subsection per
/// `$defs` entry it references (object fields as a table, an enum as a
/// variant list).
fn render_schema_section(title: &str, root: &serde_json::Value) -> String {
    let mut out = format!("## {title}\n\n");
    if let Some(desc) = root.get("description").and_then(|v| v.as_str()) {
        out.push_str(desc);
        out.push_str("\n\n");
    }
    out.push_str("### Top level\n\n");
    out.push_str(&render_object_table(root));
    if let Some(defs) = root.get("$defs").and_then(|v| v.as_object()) {
        let mut names: Vec<&String> = defs.keys().collect();
        names.sort();
        for name in names {
            let def = &defs[name];
            out.push_str(&format!("### `{name}`\n\n"));
            if let Some(desc) = def.get("description").and_then(|v| v.as_str()) {
                out.push_str(desc);
                out.push_str("\n\n");
            }
            let table = render_object_table(def);
            let table = if table.is_empty() {
                render_enum_table(def)
            } else {
                table
            };
            out.push_str(&table);
        }
    }
    out
}

/// The complete human reference page, both schemas one after another.
fn render_reference_md(config: &serde_json::Value, knowledge: &serde_json::Value) -> String {
    let mut out = String::from(
        "# vouch config and knowledge reference\n\n\
         Generated from the structs vouch actually reads — `Raw` in `src/config.rs` for \
         `config.toml`, and `Knowledge` in `src/guards.rs` for `knowledge.toml` and \
         `my-knowledge.toml` — so this page can never describe a shape either loader does \
         not actually accept.\n\n\
         Do not hand-edit this file. Regenerate it with `vouch schema config --write` (or \
         `vouch schema knowledge --write` — either one writes the complete set), then review \
         the diff.\n\n",
    );
    out.push_str(&render_schema_section("config.toml", config));
    out.push_str(&render_schema_section(
        "knowledge.toml / my-knowledge.toml",
        knowledge,
    ));
    out
}
