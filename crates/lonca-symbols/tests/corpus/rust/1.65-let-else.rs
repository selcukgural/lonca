pub fn first_word(s: &str) -> &str {
    let Some(word) = s.split_whitespace().next() else {
        return "";
    };
    word
}
