int twice(int x) {
    typeof(x) y = x;
    typeof_unqual(y) z = y;
    return y + z;
}
