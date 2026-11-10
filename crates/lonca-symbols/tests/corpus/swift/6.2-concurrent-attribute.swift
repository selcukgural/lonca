struct Loader {
    @concurrent
    nonisolated func load() async -> Int {
        return 1
    }
}
