//! Implementation of `vouch model` CLI command for syntax and semantic descriptions
//! in `my-knowledge.toml` (CLAUDE.md §3).

use toml_edit::{Array, DocumentMut, Item, Table, value};

/// Run `vouch model` CLI subcommand.
pub fn run_model(args: &[String], home: &str) -> Result<String, String> {
    if args.is_empty() {
        return Err(
            "usage: vouch model <program|tool> <name> [options]\n\n  \
             vouch model program <name> [--subcommand <verb>...] [--value-flag <flag>...] [--write-flag <flag>...] [--changes-dir] [--evaluates-input]\n  \
             vouch model tool <name> [--snippet <field:lang>] [--write-path <field>] [--cwd-from-call]\n\n  \
             Describes objective program or tool syntax in my-knowledge.toml."
                .to_string(),
        );
    }

    let kind = args[0].as_str();
    match kind {
        "program" => {
            if args.len() < 2 {
                return Err("usage: vouch model program <name> [--subcommand <verb>...] [--all-subcommands] [--value-flag <flag>...] [--write-flag <flag>...] [--standalone-flag <flag>...] [--changes-dir] [--evaluates-input] [--update]".to_string());
            }
            model_program(&args[1..], home)
        }
        "tool" => {
            if args.len() < 2 {
                return Err("usage: vouch model tool <name> [--snippet <field:lang>] [--write-path <field>] [--cwd-from-call] [--rule <field:action:match>] [--update]".to_string());
            }
            model_tool(&args[1..], home)
        }
        other => Err(format!(
            "unknown model target: '{other}'. Expected 'program' or 'tool'."
        )),
    }
}

fn model_program(args: &[String], home: &str) -> Result<String, String> {
    let raw_name = &args[0];
    let bare_name = crate::guards::base_name(raw_name);

    let mut subcommands = Vec::new();
    let mut all_subcommands = false;
    let mut value_flags = Vec::new();
    let mut write_flags = Vec::new();
    let mut standalone_flags = Vec::new();
    let mut changes_dir: Option<String> = None;
    let mut evaluates_input = false;
    let mut update = false;

    let mut i = 1;
    while i < args.len() {
        match args[i].as_str() {
            "--all-subcommands" => {
                all_subcommands = true;
            }
            "--subcommand" => {
                if i + 1 < args.len() {
                    subcommands.push(args[i + 1].clone());
                    i += 1;
                } else {
                    return Err("--subcommand requires a verb argument".to_string());
                }
            }
            "--value-flag" => {
                if i + 1 < args.len() {
                    value_flags.push(args[i + 1].clone());
                    i += 1;
                } else {
                    return Err("--value-flag requires a flag argument".to_string());
                }
            }
            "--write-flag" => {
                if i + 1 < args.len() {
                    write_flags.push(args[i + 1].clone());
                    i += 1;
                } else {
                    return Err("--write-flag requires a flag argument".to_string());
                }
            }
            "--standalone-flag" => {
                if i + 1 < args.len() {
                    standalone_flags.push(args[i + 1].clone());
                    i += 1;
                } else {
                    return Err("--standalone-flag requires a flag argument".to_string());
                }
            }
            "--changes-dir" => {
                if i + 1 < args.len() && !args[i + 1].starts_with('-') {
                    changes_dir = Some(args[i + 1].clone());
                    i += 1;
                } else {
                    changes_dir = Some("stated".to_string());
                }
            }
            "--evaluates-input" => {
                evaluates_input = true;
            }
            "--update" => {
                update = true;
            }
            other => {
                if !other.starts_with('-') {
                    subcommands.push(other.to_string());
                } else {
                    return Err(format!("unrecognized option: {other}"));
                }
            }
        }
        i += 1;
    }

    let path = crate::knowledge::my_knowledge_path(home);
    if let Some(parent) = path.parent() {
        let _ = std::fs::create_dir_all(parent);
    }
    let existing_text = std::fs::read_to_string(&path).unwrap_or_default();

    // Check duplicate
    if let Ok(kb) = toml::from_str::<crate::guards::Knowledge>(&existing_text) {
        let exists = kb
            .program
            .iter()
            .any(|p| p.match_names.iter().any(|m| m.eq_ignore_ascii_case(&bare_name)));
        if exists && !update {
            return Err(format!(
                "`{bare_name}` is already modeled in {}.\n  \
                 use --update to overwrite or modify an existing entry.",
                crate::knowledge::display_path(&path)
            ));
        }
    }

    let mut doc: DocumentMut = if existing_text.trim().is_empty() {
        crate::knowledge::MY_KNOWLEDGE_HEADER
            .parse()
            .map_err(|e| format!("invalid header TOML: {e}"))?
    } else {
        existing_text
            .parse()
            .map_err(|e| format!("existing my-knowledge.toml is not valid TOML: {e}"))?
    };

    // If updating, remove old table if present
    if update {
        if let Some(programs) = doc.get_mut("program").and_then(|i| i.as_array_of_tables_mut()) {
            programs.retain(|tbl| {
                if let Some(matches) = tbl.get("match").and_then(|m| m.as_array()) {
                    !matches.iter().any(|val| {
                        val.as_str().map(|s| s.eq_ignore_ascii_case(&bare_name)).unwrap_or(false)
                    })
                } else {
                    true
                }
            });
        }
    }

    let mut tbl = Table::new();
    let mut match_arr = Array::new();
    match_arr.push(bare_name.as_str());
    tbl.insert("match", Item::Value(match_arr.into()));

    if all_subcommands {
        tbl.insert("all_subcommands", value(true));
    } else if !subcommands.is_empty() {
        let mut sub_arr = Array::new();
        for sub in subcommands {
            sub_arr.push(sub.as_str());
        }
        tbl.insert("subcommands", Item::Value(sub_arr.into()));
    }

    if !standalone_flags.is_empty() {
        tbl.insert("case_sensitive_flags", value(true));
        let mut flg_arr = Array::new();
        for f in standalone_flags {
            flg_arr.push(f.as_str());
        }
        tbl.insert("standalone_flags", Item::Value(flg_arr.into()));
    }

    if !value_flags.is_empty() {
        let mut vf_arr = Array::new();
        for vf in value_flags {
            vf_arr.push(vf.as_str());
        }
        tbl.insert("value_options", Item::Value(vf_arr.into()));
    }

    if !write_flags.is_empty() {
        let mut wf_arr = Array::new();
        for wf in write_flags {
            wf_arr.push(wf.as_str());
        }
        tbl.insert("write_options", Item::Value(wf_arr.into()));
    }

    if let Some(cd) = changes_dir {
        tbl.insert("changes_dir", value(cd));
    }

    if evaluates_input {
        tbl.insert("evaluates_input", value(true));
    }

    let programs = doc
        .entry("program")
        .or_insert(Item::ArrayOfTables(toml_edit::ArrayOfTables::new()))
        .as_array_of_tables_mut()
        .ok_or_else(|| "program is not an array of tables".to_string())?;
    programs.push(tbl);

    let new_text = doc.to_string();
    // Validate semantic correctness against schema before writing to disk
    crate::knowledge::validate_text(&new_text)
        .map_err(|e| format!("model validation failed: {e}"))?;

    std::fs::write(&path, &new_text).map_err(|e| {
        format!(
            "could not write {}: {e}",
            crate::knowledge::display_path(&path)
        )
    })?;

    Ok(format!(
        "modeled program `{bare_name}` in {}",
        crate::knowledge::display_path(&path)
    ))
}

fn model_tool(args: &[String], home: &str) -> Result<String, String> {
    let tool_name = &args[0];

    let mut snippet: Option<(String, String)> = None;
    let mut write_path_field: Option<String> = None;
    let mut cwd_from_call = false;
    let mut rules: Vec<crate::guards::ToolRule> = Vec::new();
    let mut update = false;

    let mut i = 1;
    while i < args.len() {
        match args[i].as_str() {
            "--snippet" => {
                if i + 1 < args.len() {
                    let pair = &args[i + 1];
                    let parts: Vec<&str> = pair.splitn(2, ':').collect();
                    if parts.len() != 2 {
                        return Err("--snippet requires <field:language> format".to_string());
                    }
                    snippet = Some((parts[0].to_string(), parts[1].to_string()));
                    i += 1;
                } else {
                    return Err("--snippet requires <field:language>".to_string());
                }
            }
            "--write-path" => {
                if i + 1 < args.len() {
                    write_path_field = Some(args[i + 1].clone());
                    i += 1;
                } else {
                    return Err("--write-path requires a field name".to_string());
                }
            }
            "--cwd-from-call" => {
                cwd_from_call = true;
            }
            "--rule" => {
                // Format: field:action:pattern
                if i + 1 < args.len() {
                    let spec = &args[i + 1];
                    let parts: Vec<&str> = spec.splitn(3, ':').collect();
                    if parts.len() < 3 {
                        return Err("--rule requires <field:action:pattern> format".to_string());
                    }
                    let action = match parts[1].to_ascii_lowercase().as_str() {
                        "allow" => crate::config::Action::Allow,
                        "ask" => crate::config::Action::Ask,
                        "deny" => crate::config::Action::Deny,
                        other => return Err(format!("invalid action '{other}' in rule")),
                    };
                    rules.push(crate::guards::ToolRule {
                        field: parts[0].to_string(),
                        action,
                        when_pattern: Some(parts[2].to_string()),
                        when_exact: None,
                        reason: None,
                        guard: None,
                    });
                    i += 1;
                } else {
                    return Err("--rule requires <field:action:pattern>".to_string());
                }
            }
            "--update" => {
                update = true;
            }
            other => return Err(format!("unrecognized option: {other}")),
        }
        i += 1;
    }

    let path = crate::knowledge::my_knowledge_path(home);
    if let Some(parent) = path.parent() {
        let _ = std::fs::create_dir_all(parent);
    }
    let existing_text = std::fs::read_to_string(&path).unwrap_or_default();

    // Check duplicate
    if let Ok(kb) = toml::from_str::<crate::guards::Knowledge>(&existing_text) {
        let exists = kb
            .tool
            .iter()
            .any(|t| t.match_names.iter().any(|m| m == tool_name));
        if exists && !update {
            return Err(format!(
                "`{tool_name}` is already modeled in {}.\n  \
                 use --update to overwrite or modify an existing entry.",
                crate::knowledge::display_path(&path)
            ));
        }
    }

    let mut doc: DocumentMut = if existing_text.trim().is_empty() {
        crate::knowledge::MY_KNOWLEDGE_HEADER
            .parse()
            .map_err(|e| format!("invalid header TOML: {e}"))?
    } else {
        existing_text
            .parse()
            .map_err(|e| format!("existing my-knowledge.toml is not valid TOML: {e}"))?
    };

    if update {
        if let Some(tools) = doc.get_mut("tool").and_then(|i| i.as_array_of_tables_mut()) {
            tools.retain(|tbl| {
                if let Some(matches) = tbl.get("match").and_then(|m| m.as_array()) {
                    !matches.iter().any(|val| val.as_str() == Some(tool_name.as_str()))
                } else {
                    true
                }
            });
        }
    }

    let mut tbl = Table::new();
    let mut match_arr = Array::new();
    match_arr.push(tool_name.as_str());
    tbl.insert("match", Item::Value(match_arr.into()));
    tbl.insert("source", value(format!("modeled via vouch model")));

    if let Some((field, lang)) = snippet {
        let mut snip_arr = toml_edit::ArrayOfTables::new();
        let mut snip_tbl = Table::new();
        snip_tbl.insert("field", value(field));
        snip_tbl.insert("language", value(lang));
        snip_arr.push(snip_tbl);
        tbl.insert("snippet", Item::ArrayOfTables(snip_arr));
    }

    if let Some(wp) = write_path_field {
        tbl.insert("write_path_field", value(wp));
    }

    if cwd_from_call {
        tbl.insert("cwd_from_call", value(true));
    }

    if !rules.is_empty() {
        let mut rule_arr = toml_edit::ArrayOfTables::new();
        for r in rules {
            let mut r_tbl = Table::new();
            r_tbl.insert("field", value(r.field));
            let act_str = match r.action {
                crate::config::Action::Allow => "allow",
                crate::config::Action::Ask => "ask",
                crate::config::Action::Deny => "deny",
            };
            r_tbl.insert("action", value(act_str));
            if let Some(pat) = r.when_pattern {
                r_tbl.insert("when_pattern", value(pat));
            }
            rule_arr.push(r_tbl);
        }
        tbl.insert("rule", Item::ArrayOfTables(rule_arr));
    }

    let tools = doc
        .entry("tool")
        .or_insert(Item::ArrayOfTables(toml_edit::ArrayOfTables::new()))
        .as_array_of_tables_mut()
        .ok_or_else(|| "tool is not an array of tables".to_string())?;
    tools.push(tbl);

    let new_text = doc.to_string();
    crate::knowledge::validate_text(&new_text)
        .map_err(|e| format!("model validation failed: {e}"))?;

    std::fs::write(&path, &new_text).map_err(|e| {
        format!(
            "could not write {}: {e}",
            crate::knowledge::display_path(&path)
        )
    })?;

    Ok(format!(
        "modeled tool `{tool_name}` in {}",
        crate::knowledge::display_path(&path)
    ))
}
