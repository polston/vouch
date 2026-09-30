---
name: vouch-model
description: Use when describing objective program syntax, CLI subcommands, value flags, write destinations, or harness/MCP tool schemas in my-knowledge.toml — enforces honest claims (CLAUDE.md §3), discovers flags, and verifies boundaries
---

# vouch-model — describe program and tool syntax in my-knowledge.toml

A vouch `unmodeled_command` or `unmodeled_tool` prompt often indicates that vouch does not yet understand a program's CLI structure or an MCP tool's parameter schema. This skill turns an unmodeled command or tool into an accurate, verified description in `my-knowledge.toml`.

Per `CLAUDE.md §3`: **Every knowledge entry is a claim that must be true.** Modeling is not granting permission; it is describing objective machine reality (subcommands, flags, write channels, directory effects). Policy authorization lives separately in `config.toml` (see `vouch-trust`).

## Core Invariants & Rules

1. **Verify reality before writing claims.**
   - For shell programs: inspect `--help`, man pages, or documentation to identify verbs, flags that take values (`value_options`), flags that specify output paths (`write_options`), and standalone flags (`standalone_flags`).
   - For harness and MCP tools: inspect the declared JSON schema (via tool definitions or harness metadata) to identify code execution fields (`snippet`), write path fields (`write_path_field`), and structured argument predicates (`[[tool.rule]]`).
2. **Never claim a directory-changer does not change directories.**
   - If a program modifies working directory (e.g. `cd`, `pushd`, or CLI tools with custom directory switches), declare `changes_dir = "stated"` (or `"unstated"` / `"stack"`).
3. **Use `vouch model` CLI command for safe editing.**
   - Program syntax:
     `vouch model program <name> [--subcommand <verb>...] [--value-flag <flag>...] [--write-flag <flag>...] [--standalone-flag <flag>...] [--changes-dir] [--evaluates-input]`
   - Tool syntax:
     `vouch model tool <name> [--snippet <field:lang>] [--write-path <field>] [--cwd-from-call] [--rule <field:action:pattern>]`
   - Use `--update` when updating existing definitions.
4. **Scope subcommands appropriately.**
   - Multi-verb tools (`kubectl`, `docker`) must name specific subcommands (`--subcommand <verb>`) rather than blanket `--all-subcommands`, so unmodeled verbs continue to ask until verified.
   - Self-contained single-purpose utilities without state-mutating subcommands may use `--all-subcommands`.
5. **Structured tool gating via `[[tool.rule]]`.**
   - For database or cloud tools, add argument rules (`--rule <field:action:pattern>`) to distinguish safe reads (`SELECT ...`) from destructive mutations (`DROP ...`).
6. **Verify after modeling.**
   - Always run `vouch doctor` to verify that `my-knowledge.toml` parses cleanly without gaps or invalid schema elements.
   - Run `vouch explain` or `vouch why` on the target command or tool call to prove recognition works as intended.
