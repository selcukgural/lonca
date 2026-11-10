func load(_ url: String) async throws -> Int {
    async let first = fetch(url)
    let second = try await fetch(url)
    return try await first + second
}

func fetch(_ url: String) async throws -> Int {
    return url.count
}
