fun firstNegative(rows: List<List<Int>>): Int? {
    for (row in rows) {
        row.forEach { if (it < 0) return it else if (it == 0) continue }
        if (row.isEmpty()) break
    }
    return null
}
