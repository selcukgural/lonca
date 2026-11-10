# Languages

Lonca reads a source file as symbols (functions, types, methods, fields):
leases are per symbol, facts are computed per symbol, and the merge joins
changes to different symbols of one file. The symbols come from tree-sitter
grammars, one for each language in the [table below](#what-each-grammar-reads).
Markdown, TOML, JSON and YAML files are split into sections, and any other
file is one symbol, `path#<file>` ([Concepts](concepts.md#symbols-and-leases)).
The [first table](#where-leases-are-per-symbol) says which is which.

## Where leases are per symbol

| Files | A lease is on | Example |
|---|---|---|
| Rust, Python, TypeScript, TSX, JavaScript, C#, Go, Java, Kotlin, C, C++, Ruby, PHP, Swift | a function, method, type or field | `src/billing.rs#Client.charge` |
| Markdown, TOML, JSON, YAML | a section | `README.md#Install.Linux` |
| anything else | the file | `logo.svg#<file>` |

The fourteen languages are the whole list: a language that is not in it is
leased by file, and two agents then can not work on one file of it at the
same time. If you need one, [open an
issue](https://github.com/selcukgural/lonca/issues); a language is added
when somebody asks for it, and so is a newer grammar.

In those fourteen, a lease on a method holds that method and nothing else:
another agent can lease and change the method next to it, and the two
changes merge. This also holds in a file with syntax its grammar can not
read, for every definition the unread part is not in
([below](#a-file-the-grammar-can-not-read)).

A grammar is part of the `lonca` you installed, and it is older than its
language: languages get new syntax every year, and a grammar learns it some
time later, or not yet. A grammar keeps what it knew, so code that was read
stays read, and the gap is always at the new end: the newest syntax of a
language may be something the grammar in your build can not read.

## A file the grammar can not read

Valid code is never refused because the grammar is behind, and from symbol
engine 18 it does not cost the file its symbols either. A grammar that meets
something it can not read goes on reading after it, so only the definition
with that syntax in it is lost:

```csharp
public static class Sequences
{
    extension<T>(IEnumerable<T> source)   // C# 14: not read
    {
        public int Length() => source.Count();   // read: Sequences.Length
    }
}

public class Meter
{
    public int Read() => Value;           // read: Meter.Read
}
```

`lonca symbols` (and the `symbols` tool of an agent) lists such a file with
`not read` on a definition the unread syntax is in and `partly read` on a
type that has one; everything without a mark is leased and changed as in
any other file.

- **The change is not refused.** The syntax check lets the file through
  and names it in `details.unread` ([Daemon protocol](../protocol.md#log)).
- **A person has to agree once.** The proposal that makes a file
  unreadable, or adds an unreadable one, waits with the reason
  `unread_file:<path>` ([Reviewing agents' work](reviewing.md)). Lonca can
  not tell new syntax from a mistake, so somebody looks.
- **What was read keeps its lease.** A change that stays inside
  definitions the grammar read needs leases on those and no more, and its
  facts name them: an edit, an added or deleted method, a new signature, a
  deleted test.
- **Everything else of the file is one piece.** A change to the unread
  part, to a definition it is in, or to the code outside definitions
  (imports too) is a change of the file and needs `path#<file>`, the lease on
  the whole file: nobody gets it while somebody else holds a symbol of the
  file. Lonca vouches only for what the
  grammar read from start to end; where it stopped, a boundary may be
  wrong, so nothing there is leased by itself.
- **The file merges by its lines.** Two changes to different definitions
  merge as long as their lines do not touch; the check that a merge kept
  every symbol is not made for such a file.
- **The rest of the repository is as before,** and the file is whole again
  when the syntax goes or a release of Lonca brings a grammar that reads
  it.

Because Lonca no longer stops a syntax error itself, set `build` and `test`
in `[verification]`: your own compiler knows your language's version
([Verification](verification.md)).

The last column of the table is a smaller gap: the grammar reads the file,
and one kind of definition in it gets no symbol of its own. It can not be
leased by itself; a change to it counts as a change to the code around it.

If your code uses syntax that the table does not list and Lonca does not
read, [open an issue](https://github.com/selcukgural/lonca/issues) with the
few lines that show it. They become a sample, and the table then says so.

## What each grammar reads

A test writes this table (`crates/lonca-symbols/tests/corpus.rs`) from
small samples of the syntax that recent versions of each language
brought, and fails when the table and the grammars disagree. A version
in it is the language's (for JavaScript the year of the standard), the
one that brought the syntax. "Nothing found" is about the samples: a
grammar may still miss something no sample has.

| Language | Files | Grammar | Versions tried | Samples | Not read | Read, with no symbol for |
|---|---|---|---|---|---|---|
| Rust | `.rs` | tree-sitter-rust 0.24.2 | 1.65 to 1.89 | 13 | 1.82: unsafe extern | nothing found |
| Python | `.py` `.pyi` | tree-sitter-python 0.25.0 | 3.8 to 3.15 | 13 | 3.13: type parameter defaults; 3.15: lazy imports | nothing found |
| TypeScript | `.ts` `.mts` `.cts` | tree-sitter-typescript 0.23.2 | 4.3 to 5.9 | 12 | 4.7: variance annotations; 5.0: export type star; 5.9: import defer | nothing found |
| TSX | `.tsx` | tree-sitter-typescript 0.23.2 | 4.9 to 5.3 | 5 | nothing found | nothing found |
| JavaScript | `.js` `.mjs` `.cjs` `.jsx` | tree-sitter-javascript 0.25.0 | 2020 to 2026 | 14 | nothing found | nothing found |
| C# | `.cs` | tree-sitter-c-sharp 0.23.5 | 9 to 14 | 36 | 11: slice pattern with a subpattern; 13: allows ref struct; 14: compound assignment operators, extension blocks, lambda parameter modifiers, null conditional assignment | nothing found |
| Go | `.go` | tree-sitter-go 0.25.0 | 1.9 to 1.27 | 7 | 1.27: generic methods | nothing found |
| Java | `.java` | tree-sitter-java 0.23.5 | 14 to 25 | 11 | 25: flexible constructor bodies, module imports | nothing found |
| Kotlin | `.kt` `.kts` | tree-sitter-kotlin-ng 1.1.0 | 1.4 to 2.3 | 11 | 2.1: guard conditions; 2.2: context parameters, multi dollar interpolation | nothing found |
| C | `.c` | tree-sitter-c 0.24.2 | 11 to 23 | 16 | 23: auto type inference, bit precise integers, embed, enum with an unsigned underlying type | nothing found |
| C++ | `.cc` `.cpp` `.cxx` `.c++` `.h` `.hh` `.hpp` `.hxx` | tree-sitter-cpp 0.23.4 | 17 to 26 | 25 | 20: modules; 23: deducing this, if consteval; 26: contracts, deleted with reason, pack indexing, reflection | nothing found |
| Ruby | `.rb` `.rake` | lonca-tree-sitter-ruby (tree-sitter-ruby 0.23.1 with a scanner fix) | 2.7 to 3.4 | 13 | nothing found | nothing found |
| PHP | `.php` | tree-sitter-php 0.25.1 | 8.0 to 8.5 | 19 | nothing found | nothing found |
| Swift | `.swift` | lonca-tree-sitter-swift (tree-sitter-swift 0.7.4 with a scanner fix) | 5.5 to 6.2 | 15 | nothing found | nothing found |
