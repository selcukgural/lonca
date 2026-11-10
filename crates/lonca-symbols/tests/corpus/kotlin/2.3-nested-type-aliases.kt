class Graph {
    typealias Node = Int

    fun neighbours(of: Node): List<Node> = listOf(of + 1)
}
