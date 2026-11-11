type Pair[T] = tuple[T, T]
type Name = str


def swap[T](p: Pair[T]) -> Pair[T]:
    return (p[1], p[0])
