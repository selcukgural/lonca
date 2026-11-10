def describe(point):
    match point:
        case (0, 0):
            return "origin"
        case {"x": x, "y": y} if x == y:
            return "diagonal"
        case [first, *rest]:
            return f"{first} and {len(rest)} more"
        case _:
            return "other"
