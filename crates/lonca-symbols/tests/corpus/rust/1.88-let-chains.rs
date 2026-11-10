pub fn positive(text: Option<&str>) -> bool {
    if let Some(t) = text
        && let Ok(n) = t.parse::<i64>()
        && n > 0
    {
        return true;
    }
    false
}
