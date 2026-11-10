#include <utility>

int left(std::pair<int, int> p) {
    auto [value, _] = p;
    auto _ = 0;
    return value;
}
