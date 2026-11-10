sealed interface Result

data object Empty : Result

fun describe(r: Result): String = r.toString()
