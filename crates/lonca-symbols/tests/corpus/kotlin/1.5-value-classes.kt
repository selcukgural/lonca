@JvmInline
value class Meters(val value: Double) {
    fun plus(other: Meters): Meters = Meters(value + other.value)
}
