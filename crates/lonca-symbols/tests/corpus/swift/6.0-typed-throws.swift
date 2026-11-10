enum ParseError: Error {
    case empty
}

func parse(_ text: String) throws(ParseError) -> Int {
    guard let first = text.first else { throw .empty }
    return Int(first.asciiValue ?? 0)
}
