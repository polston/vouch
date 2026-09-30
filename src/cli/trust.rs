use std::path::Path;
use toml_edit::{Array, DocumentMut, Item, Table};

/// Run `vouch trust` policy subcommands (path, zone, program-location).
pub fn run_trust_policy(args: &[String], home: &str, config_path: &Path) -> Result<String, String> {
    if args.is_empty() {
        return Err(
            "usage: vouch trust <path|zone|program-location> ...\n\n  \
             vouch trust path <dir>                        adds <dir>/** to write.allow_paths\n  \
             vouch trust zone <dir>                        adds <dir> to run.trust_all_under\n  \
             vouch trust program-location <under> <name>   adds a trusted repository build binary\n\n  \
             Authorizes execution boundaries in config.toml."
                .to_string(),
        );
    }

    match args[0].as_str() {
        "path" => {
            if args.len() < 2 {
                return Err("usage: vouch trust path <dir>".to_string());
            }
            trust_path(&args[1], home, config_path)
        }
        "zone" => {
            if args.len() < 2 {
                return Err("usage: vouch trust zone <dir>".to_string());
            }
            trust_zone(&args[1], home, config_path)
        }
        "program-location" => {
            if args.len() < 3 {
                return Err("usage: vouch trust program-location <under> <name>".to_string());
            }
            trust_program_location(&args[1], &args[2], home, config_path)
        }
        other => Err(format!(
            "unknown trust policy target: '{other}'. Expected 'path', 'zone', or 'program-location'."
        )),
    }
}

fn trust_path(dir: &str, home: &str, config_path: &Path) -> Result<String, String> {
    let normalized = dir.replace('\\', "/");
    let trimmed = normalized.trim_end_matches('/');

    let pattern = if trimmed.ends_with('*') {
        trimmed.to_string()
    } else {
        format!("{trimmed}/**")
    };

    if let Some(parent) = config_path.parent() {
        let _ = std::fs::create_dir_all(parent);
    }
    let existing_text = std::fs::read_to_string(config_path).unwrap_or_else(|_| "version = 1\n".into());

    // Validate config before touching it and check protected paths
    if let Ok(cfg) = crate::config::load(&existing_text) {
        let norm_dir = crate::paths::normalize(trimmed, home);
        for prot in &cfg.protected {
            if let Some(p) = crate::paths::expand_pattern(prot, home, None) {
                let norm_prot = crate::paths::normalize(&p, home);
                if norm_dir == norm_prot
                    || norm_prot.starts_with(&norm_dir)
                    || crate::paths::glob_match(&pattern, &norm_prot)
                {
                    return Err(format!(
                        "refused: '{trimmed}' contains protected path '{prot}'. Protected paths can never be added to write.allow_paths."
                    ));
                }
            }
        }

        if cfg.write.allow_paths.iter().any(|p| p == &pattern || p == trimmed) {
            return Ok(format!(
                "already trusted: '{pattern}' is already in write.allow_paths in {}",
                crate::knowledge::display_path(config_path)
            ));
        }
    }

    let mut doc: DocumentMut = existing_text
        .parse()
        .map_err(|e| format!("config.toml is not valid TOML: {e}"))?;

    let write_tbl = doc
        .entry("write")
        .or_insert(Item::Table(Table::new()))
        .as_table_like_mut()
        .ok_or_else(|| "[write] is not a table".to_string())?;

    let allow_paths = write_tbl
        .entry("allow_paths")
        .or_insert(Item::Value(Array::new().into()))
        .as_array_mut()
        .ok_or_else(|| "write.allow_paths is not an array".to_string())?;

    allow_paths.push(pattern.as_str());

    let new_text = doc.to_string();
    crate::config::load(&new_text).map_err(|e| format!("config validation failed: {e}"))?;

    std::fs::write(config_path, &new_text).map_err(|e| {
        format!(
            "could not write {}: {e}",
            crate::knowledge::display_path(config_path)
        )
    })?;

    Ok(format!(
        "trusted path: added '{pattern}' to write.allow_paths in {}",
        crate::knowledge::display_path(config_path)
    ))
}

fn trust_zone(dir: &str, _home: &str, config_path: &Path) -> Result<String, String> {
    let normalized = dir.replace('\\', "/");
    let trimmed = normalized.trim_end_matches('/').to_string();

    if let Some(parent) = config_path.parent() {
        let _ = std::fs::create_dir_all(parent);
    }
    let existing_text = std::fs::read_to_string(config_path).unwrap_or_else(|_| "version = 1\n".into());

    let mut doc: DocumentMut = existing_text
        .parse()
        .map_err(|e| format!("config.toml is not valid TOML: {e}"))?;

    let run_tbl = doc
        .entry("run")
        .or_insert(Item::Table(Table::new()))
        .as_table_like_mut()
        .ok_or_else(|| "[run] is not a table".to_string())?;

    let zones = run_tbl
        .entry("trust_all_under")
        .or_insert(Item::Value(Array::new().into()))
        .as_array_mut()
        .ok_or_else(|| "run.trust_all_under is not an array".to_string())?;

    if zones.iter().any(|v| v.as_str() == Some(&trimmed)) {
        return Ok(format!(
            "already trusted: '{trimmed}' is already in run.trust_all_under in {}",
            crate::knowledge::display_path(config_path)
        ));
    }

    zones.push(trimmed.as_str());

    let new_text = doc.to_string();
    crate::config::load(&new_text).map_err(|e| format!("config validation failed: {e}"))?;

    std::fs::write(config_path, &new_text).map_err(|e| {
        format!(
            "could not write {}: {e}",
            crate::knowledge::display_path(config_path)
        )
    })?;

    Ok(format!(
        "trusted zone: added '{trimmed}' to run.trust_all_under in {}",
        crate::knowledge::display_path(config_path)
    ))
}

fn trust_program_location(under: &str, name: &str, _home: &str, config_path: &Path) -> Result<String, String> {
    let norm_under = under.replace('\\', "/").trim_end_matches('/').to_string();
    let bare_name = crate::guards::base_name(name);

    if let Some(parent) = config_path.parent() {
        let _ = std::fs::create_dir_all(parent);
    }
    let existing_text = std::fs::read_to_string(config_path).unwrap_or_else(|_| "version = 1\n".into());

    let mut doc: DocumentMut = existing_text
        .parse()
        .map_err(|e| format!("config.toml is not valid TOML: {e}"))?;

    let mut prog_tbl = Table::new();
    let mut under_arr = Array::new();
    under_arr.push(norm_under.as_str());
    prog_tbl.insert("under", Item::Value(under_arr.into()));

    let mut name_arr = Array::new();
    name_arr.push(bare_name.as_str());
    prog_tbl.insert("name_patterns", Item::Value(name_arr.into()));

    let run_item = doc.entry("run").or_insert(Item::Table(Table::new()));
    let run_tbl = run_item
        .as_table_like_mut()
        .ok_or_else(|| "[run] is not a table".to_string())?;

    let programs = run_tbl
        .entry("trust_program")
        .or_insert(Item::ArrayOfTables(toml_edit::ArrayOfTables::new()))
        .as_array_of_tables_mut()
        .ok_or_else(|| "run.trust_program is not an array of tables".to_string())?;

    programs.push(prog_tbl);

    let new_text = doc.to_string();
    crate::config::load(&new_text).map_err(|e| format!("config validation failed: {e}"))?;

    std::fs::write(config_path, &new_text).map_err(|e| {
        format!(
            "could not write {}: {e}",
            crate::knowledge::display_path(config_path)
        )
    })?;

    Ok(format!(
        "trusted program location: `{bare_name}` under '{norm_under}' in {}",
        crate::knowledge::display_path(config_path)
    ))
}
