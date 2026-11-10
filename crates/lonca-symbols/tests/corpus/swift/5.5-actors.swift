actor Counter {
    private var value = 0

    func next() -> Int {
        value += 1
        return value
    }

    nonisolated func name() -> String {
        return "counter"
    }
}
