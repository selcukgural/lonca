int apply() {
    auto first = []<typename T>(const T &a, const T &) { return a; };
    return first(1, 2);
}
