//! Text on its way to a person's terminal.
//!
//! Much of what Lonca prints was written by an agent: an intent, a path, a
//! denial reason that quotes one, the lines of a diff. A terminal obeys
//! what it reads: an escape sequence moves the cursor, clears a line or
//! hides text, a carriage return writes over what stood there, a
//! bidirectional control shows text in another order than it has. A person
//! approves from what the screen shows, so none of it may reach the screen
//! as it is. JSON output needs none of this: a JSON string has no raw
//! control character.

use std::borrow::Cow;

/// Does a terminal act on `c` instead of showing it? Every control
/// character but the newline and the tab (C0, DEL, C1, so no escape
/// sequence and no carriage return), the bidirectional controls, and the
/// line and paragraph separators.
fn acts(c: char) -> bool {
    match c {
        '\n' | '\t' => false,
        '\u{061C}'
        | '\u{200E}'
        | '\u{200F}'
        | '\u{2028}'..='\u{202E}'
        | '\u{2066}'..='\u{2069}' => true,
        c => c.is_control(),
    }
}

/// `text` as a terminal may have it: what the terminal would act on is
/// written out (`\u{1b}`, `\r`, `\u{202e}`), so it is seen and does
/// nothing. Lines and tabs stay.
pub fn printable(text: &str) -> Cow<'_, str> {
    if !text.chars().any(acts) {
        return Cow::Borrowed(text);
    }
    let mut out = String::with_capacity(text.len() + 16);
    for c in text.chars() {
        if acts(c) {
            out.extend(c.escape_default());
        } else {
            out.push(c);
        }
    }
    Cow::Owned(out)
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn plain_text_is_borrowed_as_it_is() {
        let text = "#12 change.propose agent:claude/ses_1\n\tsafer charge: ğüşiöç ✓ `a`\n";
        assert!(matches!(printable(text), Cow::Borrowed(t) if t == text));
        assert_eq!(printable(""), "");
    }

    #[test]
    fn what_a_terminal_would_act_on_is_shown_instead() {
        // Erase the line and go up one: the next entry would be drawn over.
        assert_eq!(
            printable("fix\x1b[2K\x1b[1A\r#7 ok"),
            "fix\\u{1b}[2K\\u{1b}[1A\\r#7 ok"
        );
        // Concealed text, a C1 CSI, DEL, NUL, backspace, bell.
        assert_eq!(printable("a\x1b[8mb"), "a\\u{1b}[8mb");
        assert_eq!(printable("x\u{9b}31my"), "x\\u{9b}31my");
        assert_eq!(printable("a\x7f\0\x08\x07"), "a\\u{7f}\\u{0}\\u{8}\\u{7}");
        // Text shown in another order than it has, and separators that
        // start a line without being one.
        assert_eq!(
            printable("ab\u{202E}cd\u{2066}e\u{200F}\u{061C}"),
            "ab\\u{202e}cd\\u{2066}e\\u{200f}\\u{61c}"
        );
        assert_eq!(printable("a\u{2028}b\u{2029}c"), "a\\u{2028}b\\u{2029}c");
        // A CRLF file's lines end in a visible `\r`.
        assert_eq!(printable("+one\r\n+two\n"), "+one\\r\n+two\n");
    }

    #[test]
    fn the_result_has_nothing_left_to_act_on() {
        let all: String = (0..=0x2100u32).filter_map(char::from_u32).collect();
        let out = printable(&all);
        assert!(!out.chars().any(acts), "{out:?}");
        assert_eq!(out.matches('\n').count(), 1);
        assert_eq!(out.matches('\t').count(), 1);
    }
}
