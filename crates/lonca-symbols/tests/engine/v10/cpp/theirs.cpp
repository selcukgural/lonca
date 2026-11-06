#include <vector>

using std::vector;

namespace app {

/// A client.
template <typename T>
class Client : public Base {
public:
    Client(int total);
    ~Client();
    int charge(int amount) { return total + amount; }
    int charge(long amount) const { return total - 1; }
    operator bool() const;

private:
    int total = 0;
};

Client::Client(int total) : total(total) {}

int run(int x) {
    return x + 1;
}

int other() {
    return 2;
}

} // namespace app

extern "C" {
int exported(void) { return 1; }
}

TEST(Suite, Works) {
    EXPECT_EQ(1, 1);
}

TEST(Suite, DISABLED_Later) {
    EXPECT_EQ(1, 2);
}
