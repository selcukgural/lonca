#include <concepts>

template <typename T>
concept Addable = requires(T a, T b) { a + b; };

template <typename T>
concept Small = sizeof(T) <= 8;

struct Task {
    struct promise_type {
        int get();
    };
    struct node *next;
    struct { int a; } anon;
    class Later;
    enum class State { Ready, Done };
    void run();
};
