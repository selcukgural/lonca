def render(names):
    return f"{", ".join(f"{n!r:>{10}}" for n in names)}"
