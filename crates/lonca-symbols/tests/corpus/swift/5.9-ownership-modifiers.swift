struct Token: ~Copyable {
    let id: Int

    consuming func finish() -> Int {
        return id
    }
}

func use(_ token: borrowing Token, _ other: consuming Token) -> Int {
    let moved = consume other
    return token.id + moved.finish()
}
