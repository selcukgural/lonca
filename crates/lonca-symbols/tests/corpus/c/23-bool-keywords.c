bool is_even(int x) {
    static_assert(sizeof(bool) == 1);
    return x % 2 == 0 ? true : false;
}
