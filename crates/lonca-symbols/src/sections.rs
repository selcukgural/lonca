//! Engine 1: sections of the files that have no grammar here, so that two
//! agents can work in one `README.md` or `Cargo.toml` at the same time.
//!
//! Lightweight and deterministic, on purpose. A file that is not plainly what
//! it should be has no sections, and the caller falls back to the whole file:
//! that is the fail-closed answer, never a guess.
//!
//! Names use the `.` hierarchy of symbols (`Install.Linux`,
//! `dependencies.serde`), so a lease on a section covers what is in it. A `.`
//! or `#` inside a heading or a key becomes `-`.

use std::collections::BTreeSet;

pub const PREAMBLE: &str = "<module>";
/// The tail of a Markdown section that only grew: an addition, not an edit.
pub const APPEND: &str = "<append>";

const MODULE_KEYS: &[&str] = &[
    "dependencies",
    "devDependencies",
    "optionalDependencies",
    "peerDependencies",
    "scripts",
];

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum Format {
    Markdown,
    Toml,
    Json,
    Yaml,
}

impl Format {
    pub fn detect(path: &str) -> Option<Format> {
        let (_, ext) = path.rsplit_once('.')?;
        Some(match ext {
            "md" | "markdown" => Format::Markdown,
            "toml" => Format::Toml,
            "json" => Format::Json,
            "yml" | "yaml" => Format::Yaml,
            _ => return None,
        })
    }
}

/// One named part of a file, in file order. Concatenated, the texts of a
/// Markdown, TOML or YAML file are the file. JSON is joined by [`merge_json`].
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct Section {
    pub name: String,
    pub text: String,
}

fn slug(s: &str) -> String {
    s.trim().replace(['.', '#'], "-")
}

/// Cuts `text` at the given `(offset, name)` starts. Text before the first
/// start is the preamble.
fn cut(text: &str, starts: Vec<(usize, String)>) -> Option<Vec<Section>> {
    let mut out = Vec::new();
    let first = starts.first().map_or(text.len(), |s| s.0);
    if first > 0 {
        out.push(Section {
            name: PREAMBLE.into(),
            text: text[..first].to_string(),
        });
    }
    for (i, (start, name)) in starts.iter().enumerate() {
        let end = starts.get(i + 1).map_or(text.len(), |s| s.0);
        out.push(Section {
            name: name.clone(),
            text: text[*start..end].to_string(),
        });
    }
    let mut seen = BTreeSet::new();
    let unique = out.iter().all(|s| seen.insert(s.name.as_str()));
    unique.then_some(out)
}

/// Lines with the offset each starts at.
fn lines(text: &str) -> impl Iterator<Item = (usize, &str)> {
    text.split_inclusive('\n').scan(0, |at, l| {
        let start = *at;
        *at += l.len();
        Some((start, l))
    })
}

// ---------------------------------------------------------------- Markdown

fn heading(line: &str) -> Option<(usize, &str)> {
    let t = line.trim_end();
    let indent = t.len() - t.trim_start_matches(' ').len();
    if indent > 3 {
        return None;
    }
    let t = &t[indent..];
    let level = t.len() - t.trim_start_matches('#').len();
    if !(1..=6).contains(&level) {
        return None;
    }
    let rest = t[level..].strip_prefix(' ')?;
    Some((level, rest.trim().trim_end_matches('#').trim()))
}

fn fence(line: &str) -> Option<&str> {
    let t = line.trim_start();
    ["```", "~~~"].into_iter().find(|f| t.starts_with(f))
}

fn markdown(text: &str) -> Option<Vec<Section>> {
    let mut starts = Vec::new();
    let mut open: Vec<(usize, String)> = Vec::new();
    let mut fenced: Option<&str> = None;
    for (at, line) in lines(text) {
        if let Some(f) = fence(line) {
            match fenced {
                None => fenced = Some(f),
                Some(o) if o == f => fenced = None,
                Some(_) => {}
            }
            continue;
        }
        if fenced.is_some() {
            continue;
        }
        let Some((level, title)) = heading(line) else {
            continue;
        };
        if title.is_empty() {
            return None;
        }
        open.retain(|(l, _)| *l < level);
        let mut name: Vec<&str> = open.iter().map(|(_, n)| n.as_str()).collect();
        let own = slug(title);
        name.push(&own);
        let name = name.join(".");
        starts.push((at, name));
        open.push((level, own));
    }
    cut(text, starts)
}

// ---------------------------------------------------------------- TOML

/// What a line leaves open after it: brackets, and a multi-line string.
#[derive(Default)]
struct TomlValue {
    depth: i32,
    string: Option<&'static str>,
}

impl TomlValue {
    fn read(&mut self, line: &str) {
        let b = line.as_bytes();
        let mut i = 0;
        while i < b.len() {
            if let Some(q) = self.string {
                match line[i..].find(q) {
                    Some(n) => {
                        i += n + q.len();
                        self.string = None;
                    }
                    None => return,
                }
                continue;
            }
            let rest = &line[i..];
            if let Some(q) = ["\"\"\"", "'''"].into_iter().find(|q| rest.starts_with(q)) {
                self.string = Some(q);
                i += 3;
                continue;
            }
            match b[i] {
                b'#' => return,
                b'"' | b'\'' => match skip_string(rest, b[i] as char) {
                    Some(n) => i += n,
                    None => return,
                },
                b'[' | b'{' => self.depth += 1,
                b']' | b'}' => self.depth -= 1,
                _ => {}
            }
            i += 1;
        }
    }

    fn open(&self) -> bool {
        self.depth > 0 || self.string.is_some()
    }
}

/// The offset of the closing quote of the string at the start of `s`.
fn skip_string(s: &str, quote: char) -> Option<usize> {
    let mut escaped = false;
    for (i, c) in s.char_indices().skip(1) {
        match c {
            '\\' if quote == '"' && !escaped => escaped = true,
            c if c == quote && !escaped => return Some(i),
            _ => escaped = false,
        }
    }
    None
}

fn toml(text: &str) -> Option<Vec<Section>> {
    toml::from_str::<toml::Table>(text).ok()?;
    let mut starts = Vec::new();
    let mut table = String::new();
    let mut arrays: Vec<(String, usize)> = Vec::new();
    let mut value = TomlValue::default();
    // Comments and blank lines go with what follows them.
    let mut pending = None;
    for (at, line) in lines(text) {
        if value.open() {
            value.read(line);
            continue;
        }
        let t = line.trim();
        if t.is_empty() || t.starts_with('#') {
            pending.get_or_insert(at);
            continue;
        }
        let start = pending.take().unwrap_or(at);
        let name = if let Some(h) = t.strip_prefix("[[") {
            let h = h.split("]]").next()?.trim();
            let n = match arrays.iter_mut().find(|(a, _)| a == h) {
                Some((_, n)) => {
                    *n += 1;
                    *n
                }
                None => {
                    arrays.push((h.to_string(), 0));
                    0
                }
            };
            table = format!("{}[{n}]", h.replace(['"', '\''], ""));
            table.clone()
        } else if let Some(h) = t.strip_prefix('[') {
            let h = h.split(']').next()?.trim();
            table = h.replace(['"', '\''], "");
            table.clone()
        } else {
            let key = t.split('=').next()?.trim().replace(['"', '\''], "");
            value.read(t.split_once('=')?.1);
            if table.is_empty() {
                key
            } else {
                format!("{table}.{key}")
            }
        };
        starts.push((start, name));
    }
    cut(text, starts)
}

// ---------------------------------------------------------------- YAML

fn yaml_key(line: &str) -> Option<&str> {
    let (key, rest) = line.split_once(':')?;
    let plain = !key.is_empty() && !key.starts_with(['-', '#', ' ', '{', '[', '}', ']']);
    (plain && (rest.is_empty() || rest.starts_with([' ', '\n', '\r']))).then_some(key)
}

/// A value on the line itself, a block scalar included, has no children.
fn opens_mapping(line: &str) -> bool {
    line.split_once(':')
        .is_some_and(|(_, v)| v.trim().is_empty() || v.trim().starts_with('#'))
}

fn yaml(text: &str) -> Option<Vec<Section>> {
    let mut starts = Vec::new();
    let mut top = String::new();
    let mut mapping = false;
    let mut child_indent = None;
    let mut pending = None;
    for (at, line) in lines(text) {
        let body = line.trim_end();
        let t = body.trim_start();
        if t.is_empty() || t.starts_with('#') {
            pending.get_or_insert(at);
            continue;
        }
        if body.starts_with('\t') || body.trim_start_matches(' ').starts_with('\t') {
            return None;
        }
        let indent = body.len() - t.len();
        if indent == 0 {
            if body == "---" && starts.is_empty() {
                continue;
            }
            let key = yaml_key(body)?;
            let start = pending.take().unwrap_or(at);
            top = slug(key.trim_matches(['"', '\'']));
            mapping = opens_mapping(body);
            child_indent = None;
            starts.push((start, top.clone()));
            continue;
        }
        let at_children = mapping && *child_indent.get_or_insert(indent) == indent;
        if child_indent.is_some_and(|c| indent < c) {
            return None;
        }
        match yaml_key(t).filter(|_| at_children) {
            Some(key) => {
                let start = pending.take().unwrap_or(at);
                let key = slug(key.trim_matches(['"', '\'']));
                starts.push((start, format!("{top}.{key}")));
            }
            None => {
                if at_children && t.starts_with('-') {
                    mapping = false;
                }
                pending = None;
            }
        }
    }
    cut(text, starts)
}

// ---------------------------------------------------------------- JSON

/// One side of `{...}`: what surrounds the members, and how they are joined.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct JsonObject {
    open: String,
    separator: String,
    close: String,
    members: Vec<(String, String)>,
}

/// The offset just past the JSON value at the start of `s`.
fn value_end(s: &str) -> Option<usize> {
    let mut depth = 0i32;
    let mut i = 0;
    let b = s.as_bytes();
    while i < b.len() {
        match b[i] {
            b'"' => i += skip_string(&s[i..], '"')?,
            b'{' | b'[' => depth += 1,
            b'}' | b']' if depth == 0 => return Some(i),
            b'}' | b']' => {
                depth -= 1;
                if depth == 0 {
                    return Some(i + 1);
                }
            }
            b',' if depth == 0 => return Some(i),
            _ => {}
        }
        i += 1;
        if depth == 0 && i < b.len() && b[i - 1] == b'"' {
            return Some(i);
        }
    }
    (depth == 0).then_some(b.len())
}

fn json_object(text: &str) -> Option<JsonObject> {
    let open_at = text.find('{')?;
    if !text[..open_at].trim().is_empty() {
        return None;
    }
    let mut i = open_at + 1;
    let mut members = Vec::new();
    let mut separator = None;
    let ws = |s: &str| s.len() - s.trim_start().len();
    i += ws(&text[i..]);
    let open = text[..i].to_string();
    while !text[i..].starts_with('}') {
        let start = i;
        let key_end = skip_string(&text[i..], '"')?;
        let key = text[i + 1..i + key_end].to_string();
        i += key_end + 1;
        i += ws(&text[i..]);
        i += 1 + ws(text[i..].strip_prefix(':')?);
        i += value_end(&text[i..])?;
        members.push((key, text[start..i].trim_end().to_string()));
        let sep_start = i;
        i += ws(&text[i..]);
        if text[i..].starts_with(',') {
            i += 1;
            i += ws(&text[i..]);
            separator.get_or_insert_with(|| text[sep_start..i].to_string());
        }
    }
    let end = members
        .last()
        .map_or(open.len(), |_| text[..i].trim_end().len());
    let close = text[end..].to_string();
    let separator = separator.unwrap_or_else(|| ",\n  ".to_string());
    Some(JsonObject {
        open,
        separator,
        close,
        members,
    })
}

fn nested(key: &str, member: &str) -> Option<JsonObject> {
    if !MODULE_KEYS.contains(&key) {
        return None;
    }
    json_object(member[member.find(':')? + 1..].trim_start())
}

fn json(text: &str) -> Option<Vec<Section>> {
    serde_json::from_str::<serde_json::Value>(text).ok()?;
    let object = json_object(text)?;
    let mut out = vec![Section {
        name: PREAMBLE.into(),
        text: format!("{}{}", object.open, object.close),
    }];
    for (key, member) in &object.members {
        let name = slug(key);
        match nested(key, member) {
            Some(inner) => {
                let head = member.find('{')?;
                out.push(Section {
                    name: name.clone(),
                    text: format!("{}{}{}", &member[..head], inner.open, inner.close),
                });
                for (k, m) in &inner.members {
                    out.push(Section {
                        name: format!("{name}.{}", slug(k)),
                        text: m.clone(),
                    });
                }
            }
            None => out.push(Section {
                name,
                text: member.clone(),
            }),
        }
    }
    let mut seen = BTreeSet::new();
    out.iter()
        .all(|s| seen.insert(s.name.clone()))
        .then_some(out)
}

// ---------------------------------------------------------------- common

/// The sections of `text`, or `None` for a file that has to be treated whole.
/// A file that is one section has nothing to tell apart.
pub fn sections(format: Format, text: &str) -> Option<Vec<Section>> {
    let s = match format {
        Format::Markdown => markdown(text),
        Format::Toml => toml(text),
        Format::Json => json(text),
        Format::Yaml => yaml(text),
    }?;
    (s.len() > 1).then_some(s)
}

/// What `new` adds at the end of `base`: the text goes in before the blank
/// lines that close a section, where a list ends. `None` for anything else.
pub fn appended<'a>(base: &str, new: &'a str) -> Option<&'a str> {
    let core = base.trim_end();
    let added = new.strip_prefix(core)?.strip_suffix(&base[core.len()..])?;
    (!added.is_empty()).then_some(added)
}

/// Both sides grew the base section at its end: the base, then ours, then
/// theirs. Set semantics: order follows ours, and nothing is lost.
fn both_appended(base: &str, ours: &str, theirs: &str) -> Option<String> {
    let (o, t) = (appended(base, ours)?, appended(base, theirs)?);
    let core = base.trim_end();
    Some(format!("{core}{o}{t}{}", &base[core.len()..]))
}

type Named = (String, String);

/// Three-way merge of named parts. `Err` names the parts both sides changed.
/// The result has ours' order; what only theirs added follows the part it
/// followed there.
fn merge_named(
    base: &[Named],
    ours: &[Named],
    theirs: &[Named],
    append: bool,
) -> Result<Vec<Named>, Vec<String>> {
    let get = |list: &[Named], name: &str| {
        let found = list.iter().find(|(n, _)| n == name);
        found.map(|(_, t)| t.clone())
    };
    let mut names: Vec<String> = ours.iter().map(|(n, _)| n.clone()).collect();
    for (i, (name, _)) in theirs.iter().enumerate() {
        if names.contains(name) {
            continue;
        }
        let before = theirs[..i].iter().rev();
        let after = before.filter_map(|(n, _)| names.iter().position(|x| x == n));
        let at = after.into_iter().next().map_or(0, |p| p + 1);
        names.insert(at, name.clone());
    }
    let mut out = Vec::new();
    let mut conflicts = Vec::new();
    for name in names {
        let (b, o, t) = (get(base, &name), get(ours, &name), get(theirs, &name));
        let merged = if o == t || b == t {
            o
        } else if b == o {
            t
        } else if let (true, Some(b), Some(o), Some(t)) = (append, &b, &o, &t)
            && let Some(joined) = both_appended(b, o, t)
        {
            Some(joined)
        } else {
            conflicts.push(name);
            continue;
        };
        if let Some(text) = merged {
            out.push((name, text));
        }
    }
    conflicts.is_empty().then_some(out).ok_or(conflicts)
}

fn named(s: Vec<Section>) -> Vec<Named> {
    s.into_iter().map(|x| (x.name, x.text)).collect()
}

fn concat(parts: Vec<Named>) -> String {
    let mut out = String::new();
    let count = parts.len();
    for (i, (_, text)) in parts.into_iter().enumerate() {
        out.push_str(&text);
        if i + 1 < count && !text.ends_with('\n') {
            out.push('\n');
        }
    }
    out
}

fn join(object: &JsonObject, members: Vec<Named>) -> String {
    let body: Vec<String> = members.into_iter().map(|(_, m)| m).collect();
    format!(
        "{}{}{}",
        object.open,
        body.join(&object.separator),
        object.close
    )
}

/// Members of two objects, one level into the keys that hold many.
fn merge_json(base: &str, ours: &str, theirs: &str) -> Option<Result<String, Vec<String>>> {
    let (b, o, t) = (json_object(base)?, json_object(ours)?, json_object(theirs)?);
    let inner = |side: &JsonObject, key: &str| {
        let member = side.members.iter().find(|(k, _)| k == key)?;
        nested(key, &member.1)
    };
    // A member both sides changed may still merge by its own members.
    let mut replaced = (b.members.clone(), o.members.clone(), t.members.clone());
    for (key, _) in &o.members {
        let (Some(ib), Some(io), Some(it)) = (inner(&b, key), inner(&o, key), inner(&t, key))
        else {
            continue;
        };
        let merged = match merge_named(&ib.members, &io.members, &it.members, false) {
            Ok(members) => members,
            Err(c) => {
                let c = c.iter().map(|n| format!("{}.{}", slug(key), slug(n)));
                return Some(Err(c.collect()));
            }
        };
        let member = &o.members.iter().find(|(k, _)| k == key)?.1;
        let text = format!("{}{}", &member[..member.find('{')?], join(&io, merged));
        let set = |list: &mut Vec<Named>| {
            if let Some(m) = list.iter_mut().find(|(k, _)| k == key) {
                m.1 = text.clone();
            }
        };
        set(&mut replaced.0);
        set(&mut replaced.1);
        set(&mut replaced.2);
    }
    Some(
        merge_named(&replaced.0, &replaced.1, &replaced.2, false)
            .map(|members| join(&o, members))
            .map_err(|c| c.iter().map(|n| slug(n)).collect()),
    )
}

/// Merges one file by its sections. `None` when any side has none, for the
/// caller's whole-file merge. `Err` carries the conflicting section names.
pub fn merge(format: Format, b: &str, o: &str, t: &str) -> Option<Result<String, Vec<String>>> {
    let (sb, so, st) = (
        sections(format, b)?,
        sections(format, o)?,
        sections(format, t)?,
    );
    if format == Format::Json {
        return merge_json(b, o, t);
    }
    let append = format == Format::Markdown;
    let merged = merge_named(&named(sb), &named(so), &named(st), append);
    Some(merged.map(concat))
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn the_files_with_sections_are_those_policy_reads_as_headings() {
        for path in [
            "a.md",
            "a.markdown",
            "a.toml",
            "a.json",
            "a.yml",
            "a.yaml",
            "a.rs",
            "a.cs",
            "a",
        ] {
            assert_eq!(
                Format::detect(path).is_some(),
                lonca_core::ops::names_are_headings(path),
                "{path}"
            );
        }
    }

    fn names(format: Format, text: &str) -> Vec<String> {
        let s = sections(format, text).unwrap_or_else(|| panic!("no sections: {text}"));
        s.into_iter().map(|x| x.name).collect()
    }

    fn whole(format: Format, text: &str) {
        assert_eq!(sections(format, text), None, "{text}");
    }

    /// Concatenated, the sections are the file.
    fn covers_the_file(format: Format, text: &str) {
        let s = sections(format, text).unwrap();
        let joined: String = s.iter().map(|x| x.text.as_str()).collect();
        assert_eq!(joined, text);
    }

    #[test]
    fn formats_come_from_the_extension() {
        assert_eq!(Format::detect("a/README.md"), Some(Format::Markdown));
        assert_eq!(Format::detect("x.markdown"), Some(Format::Markdown));
        assert_eq!(Format::detect("Cargo.toml"), Some(Format::Toml));
        assert_eq!(Format::detect("package.json"), Some(Format::Json));
        assert_eq!(Format::detect("c.yml"), Some(Format::Yaml));
        assert_eq!(Format::detect("c.yaml"), Some(Format::Yaml));
        assert_eq!(Format::detect("a.rs"), None);
        assert_eq!(Format::detect("Makefile"), None);
    }

    #[test]
    fn markdown_headings_nest_and_code_is_not_a_heading() {
        let text =
            "intro\n# One\ntext\n## Sub.a\n```\n# not\n~~~\n```\n### Deep #\n# Two\n    # code\n";
        assert_eq!(
            names(Format::Markdown, text),
            [PREAMBLE, "One", "One.Sub-a", "One.Sub-a.Deep", "Two"]
        );
        covers_the_file(Format::Markdown, text);
        // A sibling closes what was under the one before it.
        assert_eq!(
            names(Format::Markdown, "# A\n## B\n## C\n"),
            ["A", "A.B", "A.C"]
        );
        // No text before the first heading, no preamble; `#x` is no heading.
        assert_eq!(names(Format::Markdown, "# A\n#x\n# B\n"), ["A", "B"]);
        assert_eq!(names(Format::Markdown, "   # A\n#### B\n"), ["A", "A.B"]);
        assert_eq!(names(Format::Markdown, "# A\n####### B\n# C\n"), ["A", "C"]);
    }

    #[test]
    fn markdown_that_can_not_be_told_apart_is_whole() {
        whole(Format::Markdown, "no headings\n");
        whole(Format::Markdown, "# A\n# A\n");
        whole(Format::Markdown, "# A\n# \n");
        whole(Format::Markdown, "# Only\n");
    }

    #[test]
    fn toml_tables_and_keys_are_sections() {
        let text = "# top\nname = \"x\"\nlist = [\n  1,\n  [2],\n]\n\n# deps\n[dependencies]\n# why\nserde = \"1\"\n\"a.b\" = { version = \"2\" }\n\n[tool.poetry]\nx = \"\"\"\nmulti = 1\n[fake]\n\"\"\"\ny = 'a # b'\n[[bin]]\nn = 1\n[[bin]]\nn = 2\n";
        assert_eq!(
            names(Format::Toml, text),
            [
                "name",
                "list",
                "dependencies",
                "dependencies.serde",
                "dependencies.a.b",
                "tool.poetry",
                "tool.poetry.x",
                "tool.poetry.y",
                "bin[0]",
                "bin[0].n",
                "bin[1]",
                "bin[1].n",
            ]
        );
        covers_the_file(Format::Toml, text);
        let s = sections(Format::Toml, text).unwrap();
        assert!(
            s[0].text.starts_with("# top\n"),
            "comments go with what follows"
        );
        assert!(s[2].text.starts_with("\n# deps\n[dependencies]"));
    }

    #[test]
    fn toml_that_does_not_parse_is_whole() {
        whole(Format::Toml, "a = \n");
        whole(Format::Toml, "[a]\nb = 1\nb = 2\n");
        whole(Format::Toml, "a = 1\n");
    }

    #[test]
    fn strings_and_comments_do_not_open_brackets() {
        let mut v = TomlValue::default();
        v.read("[ \"]\", '[', # ]\n");
        assert!(v.open());
        v.read("]\n");
        assert!(!v.open());
        v.read("\"\"\" one\n");
        assert!(v.open());
        v.read("two \"\"\"\n");
        assert!(!v.open());
        v.read("\"a\\\"[\"\n");
        assert!(!v.open());
        v.read("'a\\'\n");
        assert!(!v.open());
        assert_eq!(skip_string("\"abc", '"'), None);
        assert_eq!(skip_string("\"a\\\\\"", '"'), Some(4));
    }

    #[test]
    fn yaml_keys_and_one_level_down() {
        let text = "---\n# top\nname: x\njobs:\n  # why\n  build:\n    runs: a\n    steps:\n      - x\n  test:\n    runs: b\nlist:\n  - a\n  - b: c\nblock: |\n  a: b\n  c: d\nquoted.key:\n  \"sub.key\": 1\n";
        assert_eq!(
            names(Format::Yaml, text),
            [
                PREAMBLE,
                "name",
                "jobs",
                "jobs.build",
                "jobs.test",
                "list",
                "block",
                "quoted-key",
                "quoted-key.sub-key",
            ]
        );
        covers_the_file(Format::Yaml, text);
    }

    #[test]
    fn yaml_that_is_not_plainly_a_mapping_is_whole() {
        whole(Format::Yaml, "- a\n- b\n");
        whole(Format::Yaml, "a: 1\n\tb: 2\n");
        whole(Format::Yaml, "a: 1\n---\nb: 2\n");
        whole(Format::Yaml, "a: {\n  b: 1\n}\n");
        whole(Format::Yaml, "a:\n    b: 1\n  c: 2\n");
        whole(Format::Yaml, "a: 1\na: 2\n");
        whole(Format::Yaml, "a: 1\n");
        whole(Format::Yaml, "a:b\nc: 1\n");
    }

    #[test]
    fn json_members_and_one_level_into_dependencies() {
        let text = "{\n  \"name\": \"x\",\n  \"a.b\": [1, {\"c\": 2}],\n  \"dependencies\": {\n    \"left\": \"1\",\n    \"right\": \"2\"\n  },\n  \"other\": {\"deep\": 1},\n  \"n\": 12\n}\n";
        assert_eq!(
            names(Format::Json, text),
            [
                PREAMBLE,
                "name",
                "a-b",
                "dependencies",
                "dependencies.left",
                "dependencies.right",
                "other",
                "n",
            ]
        );
        let s = sections(Format::Json, text).unwrap();
        assert_eq!(s[1].text, "\"name\": \"x\"");
        assert_eq!(s[6].text, "\"other\": {\"deep\": 1}");
    }

    #[test]
    fn json_that_is_not_an_object_of_members_is_whole() {
        whole(Format::Json, "[1, 2]\n");
        whole(Format::Json, "{\"a\": \n");
        whole(Format::Json, "{}\n");
        whole(Format::Json, "{\"a\": 1, \"a\": 2}\n");
    }

    fn merged(format: Format, b: &str, o: &str, t: &str) -> String {
        merge(format, b, o, t).unwrap().unwrap()
    }

    fn conflict(format: Format, b: &str, o: &str, t: &str) -> Vec<String> {
        merge(format, b, o, t).unwrap().unwrap_err()
    }

    #[test]
    fn markdown_edits_under_two_headings_merge_and_one_heading_conflicts() {
        let b = "# A\none\n# B\ntwo\n";
        assert_eq!(
            merged(
                Format::Markdown,
                b,
                "# A\nONE\n# B\ntwo\n",
                "# A\none\n# B\nTWO\n"
            ),
            "# A\nONE\n# B\nTWO\n"
        );
        assert_eq!(
            conflict(
                Format::Markdown,
                b,
                "# A\nx\n# B\ntwo\n",
                "# A\ny\n# B\ntwo\n"
            ),
            ["A"]
        );
        // The same edit on both sides is one edit.
        let same = "# A\nx\n# B\ntwo\n";
        assert_eq!(merged(Format::Markdown, b, same, same), same);
    }

    #[test]
    fn additions_at_the_end_of_a_section_are_kept_from_both_sides() {
        let b = "# Log\n- one\n# Old\nx\n";
        assert_eq!(
            merged(
                Format::Markdown,
                b,
                "# Log\n- one\n- ours\n# Old\nx\n",
                "# Log\n- one\n- theirs\n# Old\nx\n",
            ),
            "# Log\n- one\n- ours\n- theirs\n# Old\nx\n"
        );
        // An edit is not an addition, in a format that has none either.
        let edited = "# Log\n- ONE\n# Old\nx\n";
        let grown = "# Log\n- one\n- theirs\n# Old\nx\n";
        assert_eq!(conflict(Format::Markdown, b, edited, grown), ["Log"]);
        assert_eq!(
            conflict(
                Format::Toml,
                "a = 1\nb = 2\n",
                "a = 12\nb = 2\n",
                "a = 13\nb = 2\n"
            ),
            ["a"]
        );
    }

    #[test]
    fn an_addition_goes_in_before_the_blank_lines_that_close_a_section() {
        assert_eq!(appended("- a\n\n", "- a\n- b\n\n"), Some("\n- b"));
        assert_eq!(appended("- a\n", "- a\n- b\n"), Some("\n- b"));
        assert_eq!(appended("- a\n", "- a\n"), None, "nothing added");
        assert_eq!(appended("- a\n", "- b\n- a\n"), None, "not at the end");
        assert_eq!(appended("- a\n\n", "- a\n- b\n"), None, "the tail changed");
        let b = "# Log\n- one\n\n# Old\nx\n";
        assert_eq!(
            merged(
                Format::Markdown,
                b,
                "# Log\n- one\n- ours\n\n# Old\nx\n",
                "# Log\n- one\n- theirs\n\n# Old\nx\n",
            ),
            "# Log\n- one\n- ours\n- theirs\n\n# Old\nx\n"
        );
    }

    #[test]
    fn sections_added_on_each_side_are_both_kept_in_place() {
        let b = "[dependencies]\nleft = \"1\"\n\n[package]\nname = \"x\"\n";
        let o = "[dependencies]\nleft = \"1\"\nours = \"1\"\n\n[package]\nname = \"x\"\n";
        let t = "[dependencies]\nleft = \"1\"\ntheirs = \"1\"\n\n[package]\nname = \"x\"\n";
        assert_eq!(
            merged(Format::Toml, b, o, t),
            "[dependencies]\nleft = \"1\"\ntheirs = \"1\"\nours = \"1\"\n\n[package]\nname = \"x\"\n"
        );
        // Added under one name with different text: a conflict.
        let t = "[dependencies]\nleft = \"1\"\nours = \"2\"\n\n[package]\nname = \"x\"\n";
        assert_eq!(conflict(Format::Toml, b, o, t), ["dependencies.ours"]);
        // A deletion on one side, untouched on the other: gone; changed on
        // the other: a conflict.
        let gone = "[dependencies]\n\n[package]\nname = \"x\"\n";
        let left = "[dependencies]\nleft = \"2\"\n\n[package]\nname = \"x\"\n";
        assert_eq!(merged(Format::Toml, b, gone, b), gone);
        assert_eq!(merged(Format::Toml, b, b, gone), gone);
        assert_eq!(conflict(Format::Toml, b, gone, left), ["dependencies.left"]);
        // A new section at the very start stays at the start.
        let first = "[aaa]\nx = 1\n\n[dependencies]\nleft = \"1\"\n\n[package]\nname = \"x\"\n";
        assert!(merged(Format::Toml, b, b, first).starts_with("[aaa]"));
    }

    #[test]
    fn a_section_without_a_final_newline_does_not_run_into_the_next() {
        let parts = vec![
            ("a".to_string(), "x".to_string()),
            ("b".into(), "y\n".into()),
        ];
        assert_eq!(concat(parts), "x\ny\n");
        assert_eq!(concat(vec![("a".to_string(), "x".to_string())]), "x");
    }

    #[test]
    fn yaml_jobs_added_on_both_sides_merge() {
        let b = "jobs:\n  build:\n    runs: a\nname: x\n";
        let o = "jobs:\n  build:\n    runs: a\n  ours:\n    runs: b\nname: x\n";
        let t = "jobs:\n  build:\n    runs: a\n  theirs:\n    runs: c\nname: x\n";
        assert_eq!(
            merged(Format::Yaml, b, o, t),
            "jobs:\n  build:\n    runs: a\n  theirs:\n    runs: c\n  ours:\n    runs: b\nname: x\n"
        );
    }

    #[test]
    fn json_dependencies_added_on_both_sides_merge_with_their_commas() {
        let at = |deps: &str| {
            format!("{{\n  \"name\": \"x\",\n  \"dependencies\": {{\n{deps}\n  }}\n}}\n")
        };
        let b = at("    \"left\": \"1\"");
        let o = at("    \"left\": \"1\",\n    \"ours\": \"1\"");
        let t = at("    \"left\": \"1\",\n    \"theirs\": \"1\"");
        let m = merged(Format::Json, &b, &o, &t);
        assert_eq!(
            m,
            at("    \"left\": \"1\",\n    \"theirs\": \"1\",\n    \"ours\": \"1\"")
        );
        assert!(serde_json::from_str::<serde_json::Value>(&m).is_ok());

        let both = at("    \"left\": \"2\"");
        let other = at("    \"left\": \"3\"");
        assert_eq!(
            conflict(Format::Json, &b, &both, &other),
            ["dependencies.left"]
        );
    }

    #[test]
    fn json_top_level_members_merge_and_conflict() {
        let b = "{\n  \"a\": 1,\n  \"b\": 2\n}\n";
        let o = "{\n  \"a\": 3,\n  \"b\": 2\n}\n";
        let t = "{\n  \"a\": 1,\n  \"b\": 4\n}\n";
        assert_eq!(
            merged(Format::Json, b, o, t),
            "{\n  \"a\": 3,\n  \"b\": 4\n}\n"
        );
        let t = "{\n  \"a\": 5,\n  \"b\": 2\n}\n";
        assert_eq!(conflict(Format::Json, b, o, t), ["a"]);
    }

    #[test]
    fn a_side_without_sections_leaves_the_merge_to_the_caller() {
        let good = "# A\nx\n# B\ny\n";
        assert!(merge(Format::Markdown, good, "no headings\n", good).is_none());
        assert!(merge(Format::Markdown, "plain\n", good, good).is_none());
        assert!(merge(Format::Markdown, good, good, "plain\n").is_none());
        assert!(merge(Format::Json, "{}", "{\"a\": 1}", "{}").is_none());
    }

    #[test]
    fn value_ends_are_found_past_strings_and_brackets() {
        assert_eq!(value_end("12,"), Some(2));
        assert_eq!(value_end("\"a,b\", x"), Some(5));
        assert_eq!(value_end("[1, [2], \"]\"], x"), Some(13));
        assert_eq!(value_end("{\"a\": 1}}"), Some(8));
        assert_eq!(value_end("true }"), Some(5));
        assert_eq!(value_end("[1"), None);
        assert_eq!(value_end("12"), Some(2));
    }
}
