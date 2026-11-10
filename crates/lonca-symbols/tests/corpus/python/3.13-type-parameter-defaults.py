class Box[T = int]:
    def get(self) -> T:
        return self.value


def make[T = str](x: T) -> T:
    return x
