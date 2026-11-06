package app

import java.util.UUID

/** A client. */
class Client(val id: Int) {
    val total: Int = 0

    constructor() : this(0)

    fun charge(amount: Int): Int {
        return total + amount
    }

    fun charge(amount: Long, why: String): Int {
        return total
    }

    companion object {
        fun make() = Client()
    }

    @Test
    fun chargesOnce() {
        assert(charge(1) == 1)
    }
}

enum class State {
    OPEN,
    SHUT;

    fun open() = this == OPEN
}

fun top(x: Int) = x
