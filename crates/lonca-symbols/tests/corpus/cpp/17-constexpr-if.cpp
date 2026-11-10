#include <type_traits>

template <typename T>
int size_of(const T &value) {
    if constexpr (std::is_integral_v<T>) {
        return sizeof(value);
    } else {
        return 0;
    }
}
