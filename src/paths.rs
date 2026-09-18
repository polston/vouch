//! Canonical path form.
//!
//! The tool this replaces lists every writable location twice in its config
//! because `/c/work` and `C:/work` do not compare equal. One canonical form
//! removes that whole class of duplication and of missed matches.
//!
//! `normalize` is textual and never touches the filesystem, so it is safe to
//! call on paths that do not exist. `resolve_links` is the filesystem half.

/// Strip one layer of matching surrounding quotes.
///
/// The parsers keep quotes in the token value, so a redirect to `"$f"` arrives
/// with the quotes attached. Left on, the target looks relative and gets the
/// working directory prepended, producing paths like `C:/claude/"$f"` that
/// match no rule and name no real file.
pub fn unquote(s: &str) -> &str {
    let t = s.trim();
    for q in ['"', '\''] {
        if t.len() >= 2 && t.starts_with(q) && t.ends_with(q) {
            return &t[1..t.len() - 1];
        }
    }
    t
}

/// Strip ONE layer of surrounding shell quoting from a tool snippet and
/// process the escapes that layer implies.
///
/// The shell already consumed one quoting layer before the snippet reached
/// vouch — `python -c "print(\"hi\")"` arrives at the program as
/// `print("hi")`, not as the four extra characters still sitting in the
/// command line — so vouch must consume exactly one layer too, no more and
/// no less. This is `unquote`'s sibling, not a replacement: `unquote` only
/// strips matching outer quotes for path resolution and never touches
/// escapes, because a path has none to unescape. A snippet's content does,
/// and getting the unescape wrong (or applying it to the wrong quoting kind)
/// hands the scanner text the interpreter never sees.
///
/// The split is on whether the text OPENS a quote, not on whether it
/// contains one anywhere:
///
/// - No leading quote at all: unquoted. The shell already dropped its own
///   backslashes before the program saw the argument, so vouch drops them
///   too here — each backslash disappears and the character after it
///   survives unchanged.
/// - Opens a single quote (`'`) and closes it: contents verbatim. Single
///   quotes make backslash ordinary — there is no escaping inside them, so
///   "closes" just means the text ends with a matching `'`.
/// - Opens a double quote (`"`) and closes it, where a trailing `"` counts
///   as closing only when it is NOT itself escaped — i.e. the run of
///   backslashes immediately before it is even (zero included). An odd run
///   means that quote is escaped content, not a terminator, so the text is
///   unclosed. When it does close: unescapes only the four characters POSIX
///   gives a backslash inside double quotes (`\"`, `\\`, `` \` ``, `\$`),
///   plus a backslash-newline line continuation, dropped entirely. Anything
///   else keeps its backslash, because `"\n"` inside a Python string literal
///   means the two characters backslash-n, not a newline — unescaping it
///   here would hand the scanner a snippet the interpreter never actually
///   receives.
/// - Opens a quote (either kind) that it never closes: unbalanced, which is
///   malformed extraction, not a quoting style vouch can process. Returned
///   completely untouched, with no backslash processing of any kind —
///   reshaping malformed text risks manufacturing something that parses
///   differently from what would actually run. The untouched text flows on
///   to a parse failure downstream, which asks rather than guessing.
pub fn unquote_snippet(s: &str) -> String {
    let t = s.trim();

    if t.starts_with('\'') {
        if t.len() >= 2 && t.ends_with('\'') {
            return t[1..t.len() - 1].to_string();
        }
        return t.to_string();
    }

    if t.starts_with('"') {
        let closed = t.len() >= 2 && t.ends_with('"') && {
            let before_closing_quote = &t[..t.len() - 1];
            let trailing_backslashes = before_closing_quote
                .chars()
                .rev()
                .take_while(|&c| c == '\\')
                .count();
            trailing_backslashes % 2 == 0
        };
        if !closed {
            return t.to_string();
        }
        let inner = &t[1..t.len() - 1];
        let mut out = String::with_capacity(inner.len());
        let mut ch = inner.chars().peekable();
        while let Some(c) = ch.next() {
            if c != '\\' {
                out.push(c);
                continue;
            }
            match ch.peek() {
                Some('"') | Some('\\') | Some('$') | Some('`') => out.push(ch.next().unwrap()),
                Some('\n') => {
                    ch.next();
                }
                _ => out.push('\\'),
            }
        }
        return out;
    }

    let mut out = String::with_capacity(t.len());
    let mut ch = t.chars();
    while let Some(c) = ch.next() {
        if c == '\\' {
            if let Some(next) = ch.next() {
                out.push(next);
            }
            continue;
        }
        out.push(c);
    }
    out
}

/// `\r\n` -> `\n`. A snippet can arrive with carriage returns intact — a
/// heredoc typed on a Windows terminal keeps them — and the scanners split
/// script text on `\n` alone, so a line count taken before this runs is
/// wrong on any snippet that has them.
pub fn normalize_newlines(s: &str) -> String {
    s.replace("\r\n", "\n")
}

/// Substitute environment variables that are actually set, using `lookup`.
///
/// vouch runs as a hook in the same environment the command will run in, so
/// `%USERPROFILE%` is a lookup rather than a guess. A name that is NOT set
/// stays as written: that is the honest result, and the caller reports it as
/// an unresolved path instead of silently passing it.
///
/// Deliberately does not evaluate anything — `$(...)` and a variable assigned
/// earlier in the same command are not in the environment and stay unresolved.
pub fn expand_env_with(raw: &str, lookup: &dyn Fn(&str) -> Option<String>) -> String {
    fn is_name(c: char) -> bool {
        c.is_ascii_alphanumeric() || c == '_'
    }

    let mut out = String::with_capacity(raw.len());
    let ch: Vec<char> = raw.chars().collect();
    let mut i = 0;
    while i < ch.len() {
        // %NAME% — cmd.exe
        if ch[i] == '%' {
            if let Some(end) = (i + 1..ch.len()).find(|&j| ch[j] == '%') {
                let name: String = ch[i + 1..end].iter().collect();
                if !name.is_empty() && name.chars().all(is_name) {
                    if let Some(v) = lookup(&name) {
                        out.push_str(&v);
                        i = end + 1;
                        continue;
                    }
                }
            }
        }
        if ch[i] == '$' {
            // $env:NAME — PowerShell
            let rest: String = ch[i..].iter().collect();
            let after = if rest.len() > 5 && rest[..5].eq_ignore_ascii_case("$env:") {
                Some(5)
            } else if ch.get(i + 1) == Some(&'{') {
                None // handled below
            } else {
                Some(1) // $NAME — bash
            };
            if let Some(skip) = after {
                let start = i + skip;
                let end = (start..ch.len())
                    .find(|&j| !is_name(ch[j]))
                    .unwrap_or(ch.len());
                let name: String = ch[start..end].iter().collect();
                if !name.is_empty() {
                    if let Some(v) = lookup(&name) {
                        out.push_str(&v);
                        i = end;
                        continue;
                    }
                }
            } else if let Some(end) = (i + 2..ch.len()).find(|&j| ch[j] == '}') {
                // ${NAME} — bash
                let name: String = ch[i + 2..end].iter().collect();
                if !name.is_empty() && name.chars().all(is_name) {
                    if let Some(v) = lookup(&name) {
                        out.push_str(&v);
                        i = end + 1;
                        continue;
                    }
                }
            }
        }
        out.push(ch[i]);
        i += 1;
    }
    out
}

/// `expand_env_with` against the real process environment.
pub fn expand_env(raw: &str) -> String {
    expand_env_with(raw, &|n| std::env::var(n).ok())
}

/// A mount point alias mapping a POSIX or shell prefix to a canonical host path.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct MountEntry {
    pub alias: String,
    pub canonical: String,
}

impl MountEntry {
    pub fn new(alias: &str, canonical: &str) -> Self {
        let clean_alias = alias.replace('\\', "/").trim_end_matches('/').to_string();
        let mut clean_canon = canonical.replace('\\', "/").trim_end_matches('/').to_string();
        if let Some(stripped) = clean_canon.strip_prefix("//?Root/") {
            clean_canon = stripped.to_string();
        }
        if let Some(stripped) = clean_canon.strip_prefix("//?/") {
            clean_canon = stripped.to_string();
        }
        if clean_canon.len() >= 2 && clean_canon.as_bytes()[1] == b':' {
            clean_canon = format!("{}{}", clean_canon[..1].to_uppercase(), &clean_canon[1..]);
        }
        Self {
            alias: clean_alias,
            canonical: clean_canon,
        }
    }
}

/// Canonicalizes a mount target path if it exists on disk, stripping UNC prefixes
/// and normalizing separators. If canonicalization fails (e.g. nonexistent directory),
/// returns the raw path with backslashes converted to forward slashes.
pub fn canonicalize_mount_target(raw: &str) -> String {
    let clean = raw.trim();
    if let Ok(c) = std::fs::canonicalize(clean) {
        let mut s = c.to_string_lossy().replace('\\', "/");
        if let Some(stripped) = s.strip_prefix("//?Root/") {
            s = stripped.to_string();
        }
        if let Some(stripped) = s.strip_prefix("//?/") {
            s = stripped.to_string();
        }
        s.trim_end_matches('/').to_string()
    } else {
        clean.replace('\\', "/").trim_end_matches('/').to_string()
    }
}

/// A collection of shell mount points for canonicalizing paths across
/// virtualized or emulated environments (such as Git Bash / MSYS2 on Windows,
/// container bind mounts, or system root symlinks on macOS/Unix).
#[derive(Clone, Debug, Default, PartialEq, Eq)]
pub struct MountTable {
    entries: Vec<MountEntry>,
}

impl MountTable {
    pub fn new() -> Self {
        Self {
            entries: Vec::new(),
        }
    }

    pub fn from_entries(mut entries: Vec<MountEntry>) -> Self {
        entries.sort_by(|a, b| b.alias.len().cmp(&a.alias.len()));
        Self { entries }
    }

    pub fn add(&mut self, alias: &str, canonical: &str) {
        let entry = MountEntry::new(alias, canonical);
        if !entry.alias.is_empty() && !entry.canonical.is_empty() {
            self.entries.retain(|e| !paths_eq(&e.alias, &entry.alias));
            self.entries.push(entry);
            self.entries.sort_by(|a, b| b.alias.len().cmp(&a.alias.len()));
        }
    }

    pub fn entries(&self) -> &[MountEntry] {
        &self.entries
    }

    pub fn resolve<'a>(&'a self, path: &'a str) -> std::borrow::Cow<'a, str> {
        if self.entries.is_empty() {
            return std::borrow::Cow::Borrowed(path);
        }
        let norm_path = path.replace('\\', "/");
        for entry in &self.entries {
            if paths_eq(&norm_path, &entry.alias) {
                return std::borrow::Cow::Owned(entry.canonical.clone());
            }
            let prefix = format!("{}/", entry.alias);
            if norm_path.len() >= prefix.len() {
                let candidate_prefix = &norm_path[..prefix.len()];
                if paths_eq(candidate_prefix, &prefix) {
                    let rest = &norm_path[prefix.len()..];
                    return std::borrow::Cow::Owned(format!("{}/{}", entry.canonical, rest));
                }
            }
        }
        std::borrow::Cow::Borrowed(path)
    }

    pub fn detect() -> Self {
        let mut table = Self::new();

        // 1. Explicit override via VOUCH_MOUNT_TABLE or VOUCH_TEMP_DIR
        if let Ok(v) = std::env::var("VOUCH_MOUNT_TABLE") {
            for pair in v.split([';', ',']) {
                if let Some((alias, target)) = pair.split_once('=') {
                    table.add(alias.trim(), target.trim());
                }
            }
        }
        if let Ok(temp) = std::env::var("VOUCH_TEMP_DIR") {
            table.add("/tmp", &canonicalize_mount_target(&temp));
        }

        // 2. Windows MSYS/Git Bash temp directory mapping
        #[cfg(windows)]
        {
            if let Ok(temp) = std::env::var("TEMP").or_else(|_| std::env::var("TMP")) {
                table.add("/tmp", &canonicalize_mount_target(&temp));
            }
        }

        // 3. Unix system mount symlinks (e.g. macOS /tmp -> /private/tmp, /var -> /private/var)
        #[cfg(unix)]
        {
            for sym in ["/tmp", "/var", "/etc"] {
                if let Ok(target) = std::fs::canonicalize(sym) {
                    let target_str = target.to_string_lossy();
                    let target_clean = target_str.trim_end_matches('/');
                    if !target_clean.is_empty() && target_clean != sym {
                        table.add(sym, target_clean);
                    }
                }
            }
        }

        table
    }

    pub fn system() -> &'static MountTable {
        static SYSTEM_MOUNTS: std::sync::OnceLock<MountTable> = std::sync::OnceLock::new();
        SYSTEM_MOUNTS.get_or_init(MountTable::detect)
    }
}

/// Canonical textual form resolving through a specified mount table. Does NOT touch the filesystem.
pub fn normalize_with_mounts(raw: &str, home: &str, mounts: &MountTable) -> String {
    let mut s = raw.replace('\\', "/");

    // Home shorthands. All of these name the SAME directory; a rule written
    // with one spelling has to match a command written with another, or the
    // rule is only as good as the caller's choice of syntax.
    const HOME_FORMS: &[&str] = &[
        "~",
        "$HOME",
        "${HOME}",
        "$env:USERPROFILE",
        "$env:HOME",
        "%USERPROFILE%",
    ];
    for form in HOME_FORMS {
        if s.eq_ignore_ascii_case(form) {
            s = home.to_string();
            break;
        }
        let with_sep = format!("{form}/");
        if s.len() >= with_sep.len() && s[..with_sep.len()].eq_ignore_ascii_case(&with_sep) {
            s = format!("{}/{}", home.trim_end_matches('/'), &s[with_sep.len()..]);
            break;
        }
    }

    let b = s.as_bytes();

    // "C:/c/foo" — the MSYS mirror form such configs are full of.
    if b.len() >= 5 && b[1] == b':' && s[2..].to_lowercase().starts_with("/c/") {
        let drive = s[..1].to_uppercase();
        s = format!("{drive}:/{}", &s[5..]);
    }
    // "/c/foo" — git-bash form. Single letter between slashes means a drive.
    else if b.len() >= 3 && b[0] == b'/' && b[2] == b'/' && (b[1] as char).is_ascii_alphabetic() {
        let drive = s[1..2].to_uppercase();
        s = format!("{drive}:/{}", &s[3..]);
    }
    // "/c" alone.
    else if b.len() == 2 && b[0] == b'/' && (b[1] as char).is_ascii_alphabetic() {
        s = format!("{}:/", s[1..2].to_uppercase());
    }

    // Uppercase the drive letter.
    if s.len() >= 2 && s.as_bytes()[1] == b':' {
        s = format!("{}{}", s[..1].to_uppercase(), &s[1..]);
    }

    s = collapse(&s);

    let resolved = mounts.resolve(&s);
    if resolved != s {
        s = resolved.into_owned();
        if s.len() >= 2 && s.as_bytes()[1] == b':' {
            s = format!("{}{}", s[..1].to_uppercase(), &s[1..]);
        }
        s = collapse(&s);
    }

    s
}

/// Canonical textual form. Resolves against the system mount table. Does NOT touch the filesystem.
pub fn normalize(raw: &str, home: &str) -> String {
    normalize_with_mounts(raw, home, MountTable::system())
}

fn collapse(s: &str) -> String {
    let has_drive = s.len() >= 2 && s.as_bytes()[1] == b':';
    let (prefix, rest) = if has_drive {
        (s[..2].to_string(), &s[2..])
    } else {
        (String::new(), s)
    };

    let mut out: Vec<&str> = Vec::new();
    for seg in rest.split('/') {
        match seg {
            "" | "." => {}
            ".." => {
                out.pop();
            }
            other => {
                // Windows filesystems ignore trailing dots and spaces on a
                // path component — `foo.` and `foo ` both name `foo` — so a
                // rule written against the plain spelling has to match the
                // padded one too, under the same platform gate `fold_case`
                // uses below (spec §6.2.1 / M2.131.2). Not a macOS semantic
                // like the case fold, so this is `windows` alone. A
                // component that trims away to nothing (e.g. `...`, which is
                // not the exact `..` parent token) keeps its original text
                // rather than vanishing from the path.
                let trimmed = if cfg!(windows) {
                    other.trim_end_matches(|c: char| c == '.' || c == ' ')
                } else {
                    other
                };
                out.push(if trimmed.is_empty() { other } else { trimmed });
            }
        }
    }

    let joined = out.join("/");
    if prefix.is_empty() {
        // POSIX path: keep the leading slash if the input had one.
        if s.starts_with('/') {
            format!("/{joined}")
        } else {
            joined
        }
    } else {
        format!("{prefix}/{joined}")
    }
}

/// Resolves a path to its true location, following directory links —
/// including for a target that does not exist YET. A link in the middle of
/// the path (a junction whose real target sits elsewhere) has to resolve
/// even when the leaf is a file about to be created, or the write lands
/// somewhere the textual, unresolved spelling never named (spec §6.1 /
/// M2.131.1).
///
/// Walks from the full path up toward the root, canonicalizing each
/// ancestor in turn, and stops at the first one that exists — the deepest
/// EXISTING ancestor. The popped components (the non-existing tail) are
/// re-appended, textually, to that ancestor's resolved form. When the input
/// already exists in full, this is exactly the old whole-path canonicalize
/// (the tail is empty). When NO ancestor exists at all — not even a real
/// root — today's fallback holds: the input is returned unchanged.
pub fn resolve_links(p: &str) -> String {
    resolve_links_with_base(p, None)
}

/// Resolve links along a path, canonicalizing to the deepest existing ancestor.
/// When `p` is relative and `base` is provided, resolves against `base`.
/// When `p` is relative and `base` is None, returns `p` unchanged to avoid
/// borrowing the test runner process's working directory (M2.47).
pub fn resolve_links_with_base(p: &str, base: Option<&std::path::Path>) -> String {
    let path = std::path::Path::new(p);
    if path.is_relative() {
        if let Some(b) = base {
            let combined = b.join(path);
            return resolve_links_absolute(&combined);
        } else {
            return p.to_string();
        }
    }
    resolve_links_absolute(path)
}

fn resolve_links_absolute(path: &std::path::Path) -> String {
    let components: Vec<std::path::Component> = path.components().collect();
    if components.is_empty() {
        return path.to_string_lossy().to_string();
    }

    // The root itself — the drive prefix and/or root separator on Windows,
    // just the root separator on POSIX — is the floor: popping past it
    // leaves no path to canonicalize.
    let root_len = components
        .iter()
        .take_while(|c| matches!(c, std::path::Component::Prefix(_) | std::path::Component::RootDir))
        .count();
    if root_len == 0 {
        return path.to_string_lossy().to_string();
    }
    let floor = root_len;

    let mut tail: Vec<String> = Vec::new();
    let mut n = components.len();
    while n >= floor {
        let candidate: std::path::PathBuf = components[..n].iter().collect();
        if let Ok(c) = std::fs::canonicalize(&candidate) {
            let mut s = c.to_string_lossy().replace('\\', "/");
            if let Some(stripped) = s.strip_prefix("//?/") {
                s = stripped.to_string();
            }
            return if tail.is_empty() {
                s
            } else {
                tail.reverse();
                format!("{}/{}", s.trim_end_matches('/'), tail.join("/"))
            };
        }
        if n == floor {
            break;
        }
        n -= 1;
        tail.push(components[n].as_os_str().to_string_lossy().to_string());
    }

    path.to_string_lossy().replace('\\', "/")
}

/// Why a path could not become existing-only evidence for a recognition
/// grant. No variant carries the local path itself: the caller already has
/// the written spelling for an interactive explanation, while tests and
/// measurements can classify the cause without copying machine paths.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum ExistingPathError {
    /// `$PROJECT_ROOT` or `$WORKSPACE_ROOT` was written but this decision has no project root.
    CannotExpandPattern,
    /// The complete path does not exist (a broken link counts as missing).
    Missing,
    /// The complete path exists but is not a regular file.
    NotRegularFile,
    /// A tree pattern's root exists but is not a directory.
    NotDirectory,
    /// The operating system refused canonicalization for another reason.
    CannotCanonicalize,
}

impl ExistingPathError {
    /// Stable wording for a configured location that is inert in the current
    /// filesystem/context. Both doctor and decision prompts use this so the
    /// same typed failure cannot acquire two explanations.
    pub fn current_state_words(self) -> &'static str {
        match self {
            Self::CannotExpandPattern => "cannot be expanded in this context",
            Self::Missing => "does not exist",
            Self::NotRegularFile => "is not a regular file",
            Self::NotDirectory => "is not a directory",
            Self::CannotCanonicalize => "cannot be canonicalized",
        }
    }
}

/// One configured executable location after expansion and existing-only
/// canonicalization. `tree` distinguishes an exact file from a trailing
/// `/**` tree without reconstructing the operator's grammar later.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct CanonicalPattern {
    pub root: String,
    pub tree: bool,
}

impl CanonicalPattern {
    /// Whether a canonical existing file is exactly this configured file or
    /// inside this configured tree. Both sides are already canonical; the
    /// shared matcher supplies platform path equality and root containment.
    pub fn matches(&self, canonical_file: &str) -> bool {
        if self.tree {
            glob_match(&format!("{}/**", self.root.trim_end_matches('/')), canonical_file)
        } else {
            paths_eq(&self.root, canonical_file)
        }
    }
}

fn canonical_text(path: &std::path::Path) -> String {
    let mut text = path.to_string_lossy().replace('\\', "/");
    if let Some(stripped) = text.strip_prefix("//?/") {
        text = stripped.to_string();
    }
    normalize(&text, "")
}

/// Logical executable name derived from a canonical file path. Windows drops
/// its platform executable suffix; other platforms treat `.exe` literally.
pub fn logical_program_name(canonical_file: &str) -> String {
    let mut name = canonical_file
        .replace('\\', "/")
        .rsplit('/')
        .next()
        .unwrap_or("")
        .to_string();
    if cfg!(windows) && name.to_ascii_lowercase().ends_with(".exe") {
        name.truncate(name.len() - 4);
    }
    name
}

fn canonicalize_complete(path: &str) -> Result<std::path::PathBuf, ExistingPathError> {
    std::fs::canonicalize(path).map_err(|e| {
        if e.kind() == std::io::ErrorKind::NotFound {
            ExistingPathError::Missing
        } else {
            ExistingPathError::CannotCanonicalize
        }
    })
}

/// Canonicalize the COMPLETE path and require an existing regular file.
///
/// This is deliberately not `resolve_links`: that sibling canonicalizes the
/// deepest existing ancestor and appends a missing tail because writes may
/// create their leaf. Recognition must never manufacture proof for a program
/// file that is not there now.
pub fn canonical_existing_file(path: &str) -> Result<String, ExistingPathError> {
    let canonical = canonicalize_complete(path)?;
    let metadata = std::fs::metadata(&canonical).map_err(|e| {
        if e.kind() == std::io::ErrorKind::NotFound {
            ExistingPathError::Missing
        } else {
            ExistingPathError::CannotCanonicalize
        }
    })?;
    if !metadata.is_file() {
        return Err(ExistingPathError::NotRegularFile);
    }
    Ok(canonical_text(&canonical))
}

/// Expand and canonicalize an exact executable path or trailing-`/**` tree
/// root. A missing build tree is an inert grant for this decision, not a load
/// error; the typed failure is also what doctor reports.
pub fn canonical_existing_pattern_root(
    pattern: &str,
    home: &str,
    project_root: Option<&str>,
) -> Result<CanonicalPattern, ExistingPathError> {
    let expanded = expand_pattern(pattern, home, project_root)
        .ok_or(ExistingPathError::CannotExpandPattern)?;
    let tree = expanded.ends_with("/**");
    let mut root = expanded.strip_suffix("/**").unwrap_or(&expanded).to_string();
    if tree && root.is_empty() {
        root.push('/');
    } else if tree
        && root.len() == 2
        && root.as_bytes()[0].is_ascii_alphabetic()
        && root.as_bytes()[1] == b':'
    {
        root.push('/');
    }
    let canonical = canonicalize_complete(&root)?;
    let metadata = std::fs::metadata(&canonical).map_err(|e| {
        if e.kind() == std::io::ErrorKind::NotFound {
            ExistingPathError::Missing
        } else {
            ExistingPathError::CannotCanonicalize
        }
    })?;
    if tree {
        if !metadata.is_dir() {
            return Err(ExistingPathError::NotDirectory);
        }
    } else if !metadata.is_file() {
        return Err(ExistingPathError::NotRegularFile);
    }
    Ok(CanonicalPattern { root: canonical_text(&canonical), tree })
}

/// Path equality follows the platform: NTFS and APFS are case-preserving
/// but case-insensitive by default, so two case-spellings name one tree
/// there; ext4 is exact. A restriction missed by a case variant fails
/// SILENT, which is why this is a semantic rule and not cosmetics
/// (spec 2026-08-06 §Path comparison).
pub fn fold_case(s: &str) -> String {
    if cfg!(any(windows, target_os = "macos")) {
        s.to_lowercase()
    } else {
        s.to_string()
    }
}

pub fn paths_eq(a: &str, b: &str) -> bool {
    fold_case(a) == fold_case(b)
}

/// A configured pattern with this machine's own directories filled in: every
/// home shorthand via `normalize`, plus `$PROJECT_ROOT` or `$WORKSPACE_ROOT`
/// (and their `${...}` bracketed forms).
///
/// `None` when the pattern names `$PROJECT_ROOT` or `$WORKSPACE_ROOT` and the
/// caller has no project or workspace root to put there. A pattern that cannot
/// be expanded matches NOTHING — never everything — which is why the absence
/// is returned rather than the raw text.
///
/// It lives here, and not in `engine`, because three different kinds of rule
/// now write patterns in this one grammar: `[write]` path rules and
/// `[protected]` (via `engine::expand`, a delegate to this), and a
/// `[[program]]` entry's `only_under` (spec 2026-08-06 §Schema). A second
/// expansion written beside the third one would be a second grammar the moment
/// either changed.
pub fn expand_pattern(pattern: &str, home: &str, project_root: Option<&str>) -> Option<String> {
    let needs_root = pattern.contains("$PROJECT_ROOT")
        || pattern.contains("${PROJECT_ROOT}")
        || pattern.contains("$WORKSPACE_ROOT")
        || pattern.contains("${WORKSPACE_ROOT}");

    let p = if needs_root {
        let root = project_root?;
        pattern
            .replace("${PROJECT_ROOT}", root)
            .replace("$PROJECT_ROOT", root)
            .replace("${WORKSPACE_ROOT}", root)
            .replace("$WORKSPACE_ROOT", root)
    } else {
        pattern.to_string()
    };
    Some(normalize(&p, home))
}

/// True when `path` is what `pattern` names: `<dir>/**` is that directory and
/// everything below it, anything else is that one path exactly. Both sides go
/// through `fold_case`, so the comparison follows the platform's own path
/// equality rather than inventing one.
///
/// Moved out of `engine` alongside `expand_pattern` for the same reason: the
/// place-scoped rules compare directories against globs, and a mirrored copy
/// of these five lines would be a second answer to "is this path in that tree".
fn wildcard_match(pat: &[u8], text: &[u8]) -> bool {
    let mut p_idx = 0;
    let mut t_idx = 0;
    let mut star_idx = None;
    let mut match_idx = 0;

    while t_idx < text.len() {
        if p_idx < pat.len() && (pat[p_idx] == b'?' || pat[p_idx] == text[t_idx]) {
            p_idx += 1;
            t_idx += 1;
        } else if p_idx < pat.len() && pat[p_idx] == b'*' {
            star_idx = Some(p_idx);
            p_idx += 1;
            match_idx = t_idx;
        } else if let Some(s) = star_idx {
            p_idx = s + 1;
            match_idx += 1;
            t_idx = match_idx;
        } else {
            return false;
        }
    }

    while p_idx < pat.len() && pat[p_idx] == b'*' {
        p_idx += 1;
    }

    p_idx == pat.len()
}

fn match_segs(pat_segs: &[&str], path_segs: &[&str]) -> bool {
    if pat_segs.is_empty() {
        return path_segs.is_empty();
    }
    if pat_segs == ["**"] {
        return true;
    }
    if pat_segs[0] == "**" {
        if match_segs(&pat_segs[1..], path_segs) {
            return true;
        }
        if !path_segs.is_empty() && match_segs(pat_segs, &path_segs[1..]) {
            return true;
        }
        return false;
    }
    if path_segs.is_empty() {
        return false;
    }
    if wildcard_match(pat_segs[0].as_bytes(), path_segs[0].as_bytes()) {
        return match_segs(&pat_segs[1..], &path_segs[1..]);
    }
    false
}

fn glob_match_advanced(pattern: &str, path: &str) -> bool {
    let pat_slash = pattern.replace('\\', "/");
    let path_slash = path.replace('\\', "/");

    let pat_anchored_root = pat_slash.starts_with('/');
    let path_anchored_root = path_slash.starts_with('/');

    if pat_anchored_root && !path_anchored_root {
        return false;
    }
    let pat_has_drive = pat_slash.len() >= 2 && pat_slash.as_bytes()[1] == b':';
    let path_has_drive = path_slash.len() >= 2 && path_slash.as_bytes()[1] == b':';
    if pat_has_drive != path_has_drive && !pat_slash.starts_with("**") {
        return false;
    }

    let pat_segs: Vec<&str> = pat_slash.split('/').filter(|s| !s.is_empty()).collect();
    let path_segs: Vec<&str> = path_slash.split('/').filter(|s| !s.is_empty()).collect();

    match_segs(&pat_segs, &path_segs)
}

pub fn glob_match(pattern: &str, path: &str) -> bool {
    let (pattern, path) = (fold_case(pattern), fold_case(path));
    if pattern == path {
        return true;
    }
    if let Some(prefix) = pattern.strip_suffix("/**") {
        if !prefix.contains('*') {
            return path == prefix || path.starts_with(&format!("{prefix}/"));
        }
    }
    glob_match_advanced(&pattern, &path)
}

/// True when `dir` is under any one of these ALREADY-EXPANDED globs. An empty
/// list is false: nothing to be under.
///
/// The caller expands first (`expand_pattern`) because it is the one that
/// knows the home and project root — and because a glob that fails to expand
/// has to drop out of the list entirely rather than be compared as raw text.
pub fn under_any(globs: &[String], dir: &str) -> bool {
    globs.iter().any(|g| glob_match(g, dir))
}

/// Resolve one scanner token exactly as the decision path does: the last
/// same-line assignment wins (including an unreadable poisoned value), absent
/// names may use the process environment, and recursive expansion is bounded.
pub fn resolve_with_assignments(
    raw: &str,
    assigned: &std::collections::HashMap<String, Option<String>>,
    pwd: Option<&str>,
) -> String {
    let lookup = |name: &str| match assigned.get(name) {
        Some(value) => value.clone(),
        None if name == "PWD" => pwd.map(str::to_string),
        None => std::env::var(name).ok(),
    };
    let mut text = unquote(raw).to_string();
    for _ in 0..4 {
        let next = expand_env_with(&text, &lookup);
        if next == text {
            break;
        }
        text = next;
    }
    unquote(&text).to_string()
}

#[cfg(test)]
mod tests {
    use super::*;

    // -- collapse: trailing dots and spaces (spec §6.2.1 / M2.131.2) --------

    #[test]
    fn collapse_trailing_dot_on_a_component() {
        let got = collapse("C:/tmp/foo./bar");
        if cfg!(windows) {
            assert_eq!(got, "C:/tmp/foo/bar");
        } else {
            assert_eq!(got, "C:/tmp/foo./bar");
        }
    }

    #[test]
    fn collapse_trailing_spaces_on_a_component() {
        let got = collapse("C:/tmp/foo  /bar");
        if cfg!(windows) {
            assert_eq!(got, "C:/tmp/foo/bar");
        } else {
            assert_eq!(got, "C:/tmp/foo  /bar");
        }
    }

    #[test]
    fn collapse_mixed_trailing_dots_and_spaces() {
        let got = collapse("C:/tmp/foo. ./bar");
        if cfg!(windows) {
            assert_eq!(got, "C:/tmp/foo/bar");
        } else {
            assert_eq!(got, "C:/tmp/foo. ./bar");
        }
    }

    #[test]
    fn collapse_leaves_a_leading_dot_alone() {
        // Only a TRAILING run is a Windows fold; a leading dot names an
        // ordinary hidden-file-style component and must survive on every
        // platform.
        assert_eq!(collapse("C:/tmp/.foo/bar"), "C:/tmp/.foo/bar");
    }

    #[test]
    fn collapse_a_component_that_trims_to_nothing_keeps_its_text() {
        // "..." is not the exact ".." parent token, so it reaches the
        // trailing-fold branch; trimming every dot would erase the
        // component entirely (`C:/tmp//bar`), which is not what the
        // filesystem does with a real three-dot name. The untouched
        // original is kept rather than an emptied segment.
        assert_eq!(collapse("C:/tmp/.../bar"), "C:/tmp/.../bar");
    }

    // -- resolve_links: deepest existing ancestor (spec §6.1 / M2.131.1) ----

    #[test]
    fn resolve_links_on_a_path_that_exists_matches_full_canonicalize() {
        let dir = std::env::temp_dir();
        let input = dir.to_string_lossy().replace('\\', "/");
        let got = resolve_links(&input);
        let want = std::fs::canonicalize(&dir).expect("temp dir canonicalizes");
        let want = want.to_string_lossy().replace('\\', "/");
        let want = want.strip_prefix("//?/").unwrap_or(&want).to_string();
        assert_eq!(got, want);
    }

    #[test]
    fn resolve_links_walks_to_the_deepest_existing_ancestor() {
        let dir = std::env::temp_dir();
        let real_dir = std::fs::canonicalize(&dir).expect("temp dir canonicalizes");
        let real_dir = real_dir.to_string_lossy().replace('\\', "/");
        let real_dir = real_dir.strip_prefix("//?/").unwrap_or(&real_dir).to_string();

        let base = dir.to_string_lossy().replace('\\', "/");
        let input = format!("{base}/vouch_paths_test_missing_ancestor/deeper/leaf.txt");
        let got = resolve_links(&input);
        assert_eq!(
            got,
            format!("{real_dir}/vouch_paths_test_missing_ancestor/deeper/leaf.txt")
        );
    }

    #[test]
    fn resolve_links_on_an_entirely_nonexistent_path_returns_input_unchanged() {
        // No existing ancestor anywhere on the chain, not even a real root
        // — kept as today's fallback behavior (spec §6.1: "an entirely
        // non-existing path keeps today's return-input-unchanged behavior").
        #[cfg(windows)]
        let input = "Q:/definitely/not/a/real/drive/on/this/machine";
        #[cfg(not(windows))]
        let input = "/definitely/not/a/real/path/on/this/machine/__vouch_paths_test__";
        assert_eq!(resolve_links(input), input);
    }

    /// A directory junction inside the resolved tail's ancestor chain: the
    /// canonicalize call that finds the deepest EXISTING ancestor follows
    /// the junction to its real target, and the not-yet-existing leaf is
    /// re-appended textually. `#[cfg(windows)]`: builds the fixture with
    /// `cmd /c mklink /J`, panics (not skips) on fixture failure, and
    /// removes it on the way out via a drop guard — same shape as the
    /// integration fixture in tests/boundary_test.rs (T2 rule 5).
    #[cfg(windows)]
    #[test]
    fn resolve_links_follows_a_junction_for_a_nonexistent_leaf() {
        struct Fixture {
            junction_dir: std::path::PathBuf,
            target_dir: std::path::PathBuf,
            link: std::path::PathBuf,
        }
        impl Drop for Fixture {
            fn drop(&mut self) {
                let _ = std::fs::remove_dir(&self.link);
                let _ = std::fs::remove_dir_all(&self.target_dir);
                let _ = std::fs::remove_dir_all(&self.junction_dir);
            }
        }

        let junction_dir = std::env::temp_dir().join("vouch_paths_unit_junction");
        let target_dir = std::env::temp_dir().join("vouch_paths_unit_junction_target");
        let _ = std::fs::remove_dir_all(&junction_dir);
        let _ = std::fs::remove_dir_all(&target_dir);
        std::fs::create_dir_all(&junction_dir)
            .unwrap_or_else(|e| panic!("could not create {}: {e}", junction_dir.display()));
        std::fs::create_dir_all(&target_dir)
            .unwrap_or_else(|e| panic!("could not create {}: {e}", target_dir.display()));
        let link = junction_dir.join("link");
        let backslash = |p: &std::path::Path| p.to_string_lossy().replace('/', "\\");
        let status = std::process::Command::new("cmd")
            .args(["/c", "mklink", "/J"])
            .arg(backslash(&link))
            .arg(backslash(&target_dir))
            .status()
            .unwrap_or_else(|e| panic!("could not run mklink: {e}"));
        assert!(status.success(), "mklink /J failed to build the junction fixture");
        let fx = Fixture { junction_dir, target_dir, link };

        let real_target = std::fs::canonicalize(&fx.target_dir).expect("junction target canonicalizes");
        let real_target = real_target.to_string_lossy().replace('\\', "/");
        let real_target = real_target.strip_prefix("//?/").unwrap_or(&real_target).to_string();

        let input = format!("{}/newfile.txt", fx.link.to_string_lossy().replace('\\', "/"));
        let got = resolve_links(&input);
        assert_eq!(got, format!("{real_target}/newfile.txt"));
    }

    #[test]
    fn resolve_links_on_a_relative_path_does_not_canonicalize_against_process_cwd() {
        // Even if a file exists in the current directory, a relative path without base returns unchanged (M2.47).
        let rel = "Cargo.toml";
        assert!(std::path::Path::new(rel).exists(), "Cargo.toml must exist in repo cwd for this test premise");
        let got = resolve_links(rel);
        assert_eq!(got, rel, "relative path without base must not borrow runner cwd");
    }

    #[test]
    fn resolve_links_with_base_on_a_relative_path_resolves_against_base() {
        let dir = std::env::temp_dir();
        let real_dir = std::fs::canonicalize(&dir).expect("temp dir canonicalizes");
        let real_dir = real_dir.to_string_lossy().replace('\\', "/");
        let real_dir = real_dir.strip_prefix("//?/").unwrap_or(&real_dir).to_string();

        let got = resolve_links_with_base("some/sub/file.txt", Some(&dir));
        assert_eq!(got, format!("{real_dir}/some/sub/file.txt"));
    }
}
