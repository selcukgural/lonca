constexpr int pick(int x) {
    if consteval {
        return x;
    } else {
        return x + 1;
    }
}
