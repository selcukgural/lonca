final class Box {
    var value = 0
}

func hand(_ box: sending Box) async -> Int {
    return box.value
}

nonisolated(unsafe) var shared = 0
