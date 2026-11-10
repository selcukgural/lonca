#include <coroutine>

struct Task;

struct Promise {
    Task get_return_object();
    std::suspend_never initial_suspend() { return {}; }
    std::suspend_never final_suspend() noexcept { return {}; }
    void return_void() {}
    void unhandled_exception() {}
};

struct Task {
    using promise_type = Promise;
};

Task Promise::get_return_object() { return {}; }

Task run() {
    co_await std::suspend_never{};
    co_return;
}
