func length(_ text: String?) -> Int {
    if let text {
        return text.count
    }
    guard let text else { return 0 }
    return text.count
}
