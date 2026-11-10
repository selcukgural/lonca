type Pair[T] = tuple[T, T]


def swap[T](p: Pair[T]) -> Pair[T]:
    return (p[1], p[0])
