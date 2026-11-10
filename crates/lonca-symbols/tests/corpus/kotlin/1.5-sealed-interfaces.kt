sealed interface Shape {
    fun area(): Double
}

class Circle(val r: Double) : Shape {
    override fun area(): Double = 3.14 * r * r
}
