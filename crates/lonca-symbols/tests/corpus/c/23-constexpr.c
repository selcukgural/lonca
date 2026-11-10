constexpr int limit = 64;

int clamp(int x) {
    return x > limit ? limit : x;
}
