type Pair[T] = list[T]
type Name = str
type Id = int


def swap[T](p: Pair[T]) -> Pair[T]:
    return (p[1], p[0])
