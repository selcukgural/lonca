class Stack[T]:
    def push(self, item: T) -> None:
        self.items.append(item)


def first[T: (int, str), *Ts, **P](items: list[T]) -> T:
    return items[0]
