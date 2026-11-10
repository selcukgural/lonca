def copy(src, dst):
    with (
        open(src) as a,
        open(dst, "w") as b,
    ):
        b.write(a.read())
