sealed interface Animal
data class Cat(val hungry: Boolean) : Animal
data class Dog(val name: String) : Animal

fun feed(animal: Animal): String = when (animal) {
    is Dog -> "dog"
    is Cat if !animal.hungry -> "later"
    is Cat -> "cat"
}
