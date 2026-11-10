#include <concepts>

template <typename T>
concept Addable = requires(T a, T b) {
    { a + b } -> std::convertible_to<T>;
};

template <Addable T>
T add(T a, T b) requires std::copyable<T> {
    return a + b;
}

auto twice(std::integral auto x) {
    return x * 2;
}
