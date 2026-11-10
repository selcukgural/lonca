template <typename... Ts>
auto sum(Ts... values) {
    return (values + ... + 0);
}
