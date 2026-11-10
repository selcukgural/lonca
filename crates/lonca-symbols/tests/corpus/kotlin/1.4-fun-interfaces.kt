fun interface Check {
    fun ok(value: Int): Boolean
}

fun positive(): Check = Check { it > 0 }
