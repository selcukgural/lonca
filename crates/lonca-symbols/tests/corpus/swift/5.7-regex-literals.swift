func isVersion(_ text: String) -> Bool {
    return text.wholeMatch(of: /v(\d+)\.(\d+)/) != nil
}
