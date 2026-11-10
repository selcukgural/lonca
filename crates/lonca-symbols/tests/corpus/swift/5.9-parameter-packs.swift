func count<each T>(_ values: repeat each T) -> Int {
    var total = 0
    repeat ((each values), total += 1).1
    return total
}
