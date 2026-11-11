//! One value of `lonca.toml` set in place (`lonca policy set --value`).
//!
//! The file is a person's: its comments and its order stay. So the text is
//! edited by line, and then both texts are read as TOML: the new one must
//! be the old one with that key set and nothing else different, or the
//! edit is refused. A value this can not place (one that spans lines, a key
//! written with dots or quotes) is for an editor and `--config`.

use toml::{Table, Value};

/// `key=value` as given on a command line: the key's path, and the value as
/// TOML when it reads as TOML (`1200`, `true`, `["a", "b"]`, `"x"`), as a
/// string otherwise (`deny`).
pub fn assignment(arg: &str) -> Result<(Vec<String>, Value), String> {
    let (key, raw) = arg
        .split_once('=')
        .ok_or_else(|| format!("{arg:?}: expected KEY=VALUE, as sessions.ops_per_minute=1200"))?;
    let path: Vec<String> = key.trim().split('.').map(str::to_string).collect();
    let bare = |p: &String| {
        !p.is_empty()
            && p.chars()
                .all(|c| c.is_ascii_alphanumeric() || c == '_' || c == '-')
    };
    if path.len() < 2 || !path.iter().all(bare) {
        return Err(format!(
            "{key:?}: a key is its table and its name, as sessions.ops_per_minute"
        ));
    }
    let raw = raw.trim();
    let value = match format!("v = {raw}").parse::<Table>() {
        Ok(mut t) if t.len() == 1 => t.remove("v"),
        _ => None,
    };
    Ok((
        path,
        value.unwrap_or_else(|| Value::String(raw.to_string())),
    ))
}

/// The value at `path`, if the text has it.
pub fn get(text: &str, path: &[String]) -> Result<Option<Value>, String> {
    let table: Table = text.parse().map_err(|e| format!("{e}"))?;
    let mut at = &Value::Table(table);
    for part in path {
        match at.get(part) {
            Some(v) => at = v,
            None => return Ok(None),
        }
    }
    Ok(Some(at.clone()))
}

/// `text` with the value at `path` set to `value`, every other line as it
/// was.
pub fn set(text: &str, path: &[String], value: &Value) -> Result<String, String> {
    let name = path.join(".");
    let Some((key, table)) = path.split_last() else {
        return Err("no key".into());
    };
    let table = table.join(".");
    let written = format!("{key} = {value}");
    let mut lines: Vec<String> = text.lines().map(str::to_string).collect();
    let mut inside = false;
    let mut header = None;
    let mut found = None;
    for (i, line) in lines.iter().enumerate() {
        let t = line.trim();
        if let Some(h) = t.strip_prefix('[') {
            let h = h.split(']').next().unwrap_or_default().trim();
            inside = !t.starts_with("[[") && h == table;
            if inside {
                header = Some(i);
            }
        } else if inside
            && let Some((k, rest)) = t.split_once('=')
            && k.trim() == key
        {
            found = Some((i, comment_of(rest)));
            break;
        }
    }
    match (found, header) {
        (Some((i, comment)), _) => {
            let indent: String = lines
                .get(i)
                .map(|l| l.chars().take_while(|c| c.is_whitespace()).collect())
                .unwrap_or_default();
            let tail = comment.map(|c| format!(" {c}")).unwrap_or_default();
            if let Some(line) = lines.get_mut(i) {
                *line = format!("{indent}{written}{tail}");
            }
        }
        (None, Some(h)) => lines.insert(h + 1, written),
        (None, None) => {
            if lines.last().is_some_and(|l| !l.trim().is_empty()) {
                lines.push(String::new());
            }
            lines.push(format!("[{table}]"));
            lines.push(written);
        }
    }
    let mut out = lines.join("\n");
    out.push('\n');

    // The edit is right when the new text reads as the old one with this
    // key set, and as nothing else.
    let mut want: Table = text.parse().map_err(|e| format!("{e}"))?;
    put(&mut want, path, value.clone())
        .ok_or_else(|| format!("{name}: a part of it is a value, not a table"))?;
    let got: Result<Table, _> = out.parse();
    if got.ok().as_ref() != Some(&want) {
        return Err(format!(
            "{name} can not be set in place in this file; edit a copy of it \
             (`lonca policy show`) and pass it with --config"
        ));
    }
    Ok(out)
}

/// Sets `path` in `table`, making the tables on the way. `None` when a part
/// of the path is there and is not a table.
fn put(table: &mut Table, path: &[String], value: Value) -> Option<()> {
    let (key, rest) = path.split_first()?;
    if rest.is_empty() {
        table.insert(key.clone(), value);
        return Some(());
    }
    let next = table
        .entry(key.clone())
        .or_insert_with(|| Value::Table(Table::new()));
    put(next.as_table_mut()?, rest, value)
}

/// The comment that ends a `key = value` line, from what follows the `=`:
/// a `#` outside a string.
fn comment_of(rest: &str) -> Option<&str> {
    let mut quote = None;
    let mut escaped = false;
    for (i, c) in rest.char_indices() {
        match quote {
            Some('"') if escaped => escaped = false,
            Some('"') if c == '\\' => escaped = true,
            Some(q) if c == q => quote = None,
            Some(_) => {}
            None if c == '"' || c == '\'' => quote = Some(c),
            None if c == '#' => return rest.get(i..),
            None => {}
        }
    }
    None
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::config::{DEFAULT_CONFIG, DEFAULT_POLICY, PolicyBundle};

    fn path(key: &str) -> Vec<String> {
        key.split('.').map(str::to_string).collect()
    }

    fn set_arg(text: &str, arg: &str) -> Result<String, String> {
        let (p, v) = assignment(arg)?;
        set(text, &p, &v)
    }

    #[test]
    fn one_line_of_the_default_file_changes_and_no_other() {
        let out = set_arg(DEFAULT_CONFIG, "sessions.ops_per_minute=1200").unwrap();
        let changed: Vec<(&str, &str)> = DEFAULT_CONFIG
            .lines()
            .zip(out.lines())
            .filter(|(a, b)| a != b)
            .collect();
        assert_eq!(changed, [("ops_per_minute = 600", "ops_per_minute = 1200")]);
        assert_eq!(DEFAULT_CONFIG.lines().count(), out.lines().count());
        let bundle = PolicyBundle::parse(&out, DEFAULT_POLICY).unwrap();
        assert_eq!(bundle.config.sessions.ops_per_minute, 1200);
        assert_eq!(
            get(&out, &path("sessions.ops_per_minute")).unwrap(),
            Some(Value::Integer(1200))
        );
    }

    #[test]
    fn the_key_of_its_own_table_is_the_one_set() {
        // `max_ttl_minutes` is in [sessions] and in [leases].
        let out = set_arg(DEFAULT_CONFIG, "leases.max_ttl_minutes=45").unwrap();
        let b = PolicyBundle::parse(&out, DEFAULT_POLICY).unwrap();
        assert_eq!(b.config.leases.max_ttl_minutes, 45);
        assert_eq!(b.config.sessions.max_ttl_minutes, 480);
    }

    #[test]
    fn a_key_the_file_leaves_out_goes_under_its_table_and_a_new_table_at_the_end() {
        let sparse = "# mine\n[leases]\nmax_items = 8\n";
        let out = set_arg(sparse, "leases.max_ttl_minutes=10").unwrap();
        assert_eq!(
            out,
            "# mine\n[leases]\nmax_ttl_minutes = 10\nmax_items = 8\n"
        );
        let out = set_arg(sparse, "sessions.ops_per_minute=30").unwrap();
        assert_eq!(
            out,
            "# mine\n[leases]\nmax_items = 8\n\n[sessions]\nops_per_minute = 30\n"
        );
        let out = set_arg("", "sessions.ops_per_minute=30").unwrap();
        assert_eq!(out, "[sessions]\nops_per_minute = 30\n");
    }

    #[test]
    fn a_comment_after_the_value_and_the_indent_stay() {
        let text = "[sessions]\n  ops_per_minute = 600   # a \"busy\" team\n";
        let out = set_arg(text, "sessions.ops_per_minute=900").unwrap();
        assert_eq!(
            out,
            "[sessions]\n  ops_per_minute = 900 # a \"busy\" team\n"
        );
        let text = "[observation]\nnetwork = \"taint\" # not # deny\n";
        let out = set_arg(text, "observation.network=deny").unwrap();
        assert_eq!(out, "[observation]\nnetwork = \"deny\" # not # deny\n");
        let text = "[x]\nnote = \"a # b\"\n";
        assert_eq!(set_arg(text, "x.note=c").unwrap(), "[x]\nnote = \"c\"\n");
    }

    #[test]
    fn a_value_reads_as_toml_and_as_a_string_when_it_does_not() {
        let v = |arg: &str| assignment(arg).unwrap().1;
        assert_eq!(v("a.b=12"), Value::Integer(12));
        assert_eq!(v("a.b = true"), Value::Boolean(true));
        assert_eq!(v("a.b=deny"), Value::String("deny".into()));
        assert_eq!(v("a.b=\"12\""), Value::String("12".into()));
        assert_eq!(v("a.b=x=y"), Value::String("x=y".into()));
        assert_eq!(
            v("a.b=[80, 443]"),
            Value::Array(vec![Value::Integer(80), Value::Integer(443)])
        );
        // Not a second key on the side.
        assert_eq!(v("a.b=1\nc = 2"), Value::String("1\nc = 2".into()));
    }

    #[test]
    fn what_is_no_assignment_is_refused() {
        for bad in [
            "ops_per_minute=3",
            "sessions.ops_per_minute",
            ".x=1",
            "a..b=1",
            "a.\"b\"=1",
            "a.b c=1",
            "=1",
        ] {
            assert!(assignment(bad).is_err(), "{bad}");
        }
    }

    #[test]
    fn a_value_over_several_lines_is_left_to_an_editor() {
        let text = "[observation]\nallow_ports = [\n  80,\n  443,\n]\n";
        let e = set_arg(text, "observation.allow_ports=[80]").unwrap_err();
        assert!(e.contains("--config"), "{e}");
        // On one line it is set.
        let text = "[observation]\nallow_ports = [80, 443]\n";
        let out = set_arg(text, "observation.allow_ports=[80]").unwrap();
        assert_eq!(out, "[observation]\nallow_ports = [80]\n");
    }

    #[test]
    fn a_key_written_another_way_is_left_to_an_editor() {
        // Dotted in the root table: a second definition would not parse.
        let text = "sessions.ops_per_minute = 600\n";
        assert!(set_arg(text, "sessions.ops_per_minute=3").is_err());
        // A table that is a value.
        assert!(set_arg("a = 1\n", "a.b=2").is_err());
        // An array of tables is not the table.
        let text = "[[paths.keyed]]\ndir = \"m\"\n";
        assert!(set_arg(text, "paths.keyed.dir=x").is_err());
    }

    #[test]
    fn a_file_that_does_not_read_is_refused() {
        assert!(set_arg("[sessions\n", "sessions.ops_per_minute=3").is_err());
        assert!(get("[sessions\n", &path("a.b")).is_err());
    }

    #[test]
    fn a_nested_table_is_reached() {
        let text = "[verification.checks]\nbuild = \"cargo build\"\n";
        let out = set_arg(text, "verification.checks.build=make").unwrap();
        assert_eq!(out, "[verification.checks]\nbuild = \"make\"\n");
        assert_eq!(
            get(&out, &path("verification.checks.nothing")).unwrap(),
            None
        );
    }
}
